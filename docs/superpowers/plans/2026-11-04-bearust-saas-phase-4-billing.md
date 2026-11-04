# Bearust SaaS Phase 4: Billing with Multiple Payment Gateways

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Organizations subscribe to paid plans and pay through the gateway that suits them (Midtrans, Xendit, Duitku, Paddle, Stripe, Dodo Payments, PayPal, and more later). Plan limits follow the subscription state. Staff manage plans, prices, gateways, subscriptions and refunds from the dashboard.

**Builds on:** Phase 3 (`2026-11-04-bearust-saas-phase-3-two-scope-rbac.md`): `org.billing.read/manage`, the platform `Billing` role and `billing.*`/`plans.manage` permissions must exist.

**Architecture:** The SaaS owns the billing domain (plans, prices, subscriptions, invoices, payments) and is the source of truth for entitlements. Each gateway is an adapter behind one Go interface; adapters only talk to their provider and translate its events into internal events. Gateways differ in what they can do, so each adapter declares capabilities:

- **Provider-managed recurring** (Stripe, Paddle, Dodo Payments, PayPal subscriptions): the provider charges every period; the SaaS mirrors state from webhooks.
- **SaaS-managed recurring** (gateways used for one-off payments, e.g. invoices, virtual accounts, QRIS, e-wallets): the SaaS issues an invoice each period, sends a payment link, and renews on payment; saved-card or tokenized recurring is used where the adapter supports it.
- **Merchant of Record** (Paddle, Dodo Payments): the provider is the seller and handles tax; the SaaS stores the provider's invoice reference instead of issuing its own tax invoice.

Every webhook is verified, stored raw, deduplicated, and processed through the queue. Entitlements are recomputed from internal state only, never straight from a webhook payload.

**Tech Stack:** Same as Phase 3. Provider SDKs only where an official Go SDK exists; otherwise plain HTTP clients with recorded fixtures.

## Facts to verify before Task 1

Provider APIs change; this plan does not rely on remembered details. Task 0 records, per provider and from its current official documentation: supported payment methods and currencies, recurring support (native subscriptions, tokenized charges, or none), checkout/payment-link API, webhook signing scheme and retry policy, refund and partial-refund support, sandbox availability, settlement currency, and Merchant of Record status. The capability matrix in `internal/billing/providers/README.md` is the output, and adapters are built against it.

## Decisions (2026-11-04)

- Billing ships together with the RBAC work as the next phases; multiple gateways are a requirement, not a later extension.
- Gateways requested: Midtrans, Xendit, Duitku, Paddle, Stripe, Dodo Payments, PayPal, extensible to more.

## Open decisions (default in bold, change before Task 3)

1. Order of adapters after the fake provider: **Xendit (IDR) and Stripe (USD) first**, then Midtrans, Duitku, Paddle, Dodo Payments, PayPal.
2. Currencies: **IDR and USD** prices per plan; a price exists per (plan, currency, interval).
3. Intervals: **monthly and yearly** (yearly with a configurable discount).
4. Failed payment: **7-day grace (`past_due`), then downgrade to Free**; existing resources stay but creating new ones over the Free limits is blocked.
5. Upgrades take effect immediately with proration as a credit on the next invoice; downgrades take effect at period end.
6. Tax for non-MoR gateways: **prices are tax-inclusive** with a configurable tax rate shown on the invoice; formal tax invoices are a follow-up.

## Global Constraints

- All earlier constraints apply.
- Money is stored as integer minor units with an ISO 4217 currency; never floats. IDR has no minor unit in practice; the currency table defines the exponent.
- Gateway credentials and webhook secrets are encrypted with `SECRETS_KEY`, never returned by the API, and editable only with `billing.manage`.
- Webhooks: signature verified with the provider's scheme before anything is stored as trusted; raw body kept for 90 days; idempotent on `(provider, provider_event_id)`; out-of-order events resolved by provider timestamps and state machine rules, not arrival order.
- No card data touches the SaaS: hosted checkout, payment links or provider-hosted fields only.
- One active subscription per organization. Plan limits come from the subscription's plan while `active`, `trialing` or `past_due`; otherwise from Free.
- Every billing state change is audited (platform audit and organization audit).
- New error codes: `PLAN_NOT_FOUND`, `PRICE_NOT_FOUND`, `GATEWAY_NOT_FOUND`, `GATEWAY_DISABLED`, `GATEWAY_UNSUPPORTED`, `SUBSCRIPTION_NOT_FOUND`, `SUBSCRIPTION_EXISTS`, `INVOICE_NOT_FOUND`, `PAYMENT_FAILED`, `WEBHOOK_INVALID`.

---

## Data model

- `currencies(code, exponent)`
- `plans` (existing) gains `active`, `sort`, `description`, `features` (jsonb for marketing copy); limits stay as columns.
- `plan_prices(id, plan_code, currency, interval, amount_minor, active, provider_refs jsonb)` — provider product/price ids per gateway where needed.
- `payment_gateways(code, display_name, enabled, mode sandbox|live, config_ciphertext, webhook_secret_ciphertext, currencies, capabilities jsonb, sort)`
- `billing_customers(org_id, gateway_code, provider_customer_id)`
- `subscriptions(id, org_id, plan_code, price_id, gateway_code, status trialing|active|past_due|canceled|expired|incomplete, managed_by provider|saas, provider_subscription_id, current_period_start, current_period_end, cancel_at_period_end, grace_until, created_at, updated_at)`
- `invoices(id, number, org_id, subscription_id, currency, subtotal_minor, tax_minor, total_minor, status draft|open|paid|void|uncollectible, due_at, paid_at, provider_invoice_ref, pdf_url)`
- `invoice_lines(invoice_id, description, quantity, unit_minor, amount_minor, period_start, period_end)`
- `payments(id, invoice_id, gateway_code, provider_payment_id, method, amount_minor, currency, status pending|succeeded|failed|refunded|partially_refunded, failure_reason, created_at)`
- `refunds(id, payment_id, amount_minor, provider_refund_id, status, reason, created_by)`
- `webhook_events(id, gateway_code, provider_event_id, type, signature_valid, payload, received_at, processed_at, error)` unique `(gateway_code, provider_event_id)`
- `org_billing_profiles(org_id, legal_name, email, address, tax_id, country)`

## Adapter interface (Go)

```go
type Gateway interface {
    Code() string
    Capabilities() Capabilities // recurring: provider|tokenized|none, refunds, partial refunds, MoR, currencies, methods
    EnsureCustomer(ctx, org BillingProfile) (CustomerRef, error)
    CreateCheckout(ctx, CheckoutRequest) (CheckoutSession, error)      // first payment or plan change; returns a redirect URL
    CreatePaymentLink(ctx, Invoice) (PaymentLink, error)                // SaaS-managed renewals
    ChargeSaved(ctx, Invoice, PaymentMethodRef) (PaymentResult, error)  // only when recurring == tokenized
    CancelSubscription(ctx, SubscriptionRef, atPeriodEnd bool) error    // only when recurring == provider
    Refund(ctx, PaymentRef, amountMinor int64) (RefundResult, error)
    VerifyWebhook(headers http.Header, body []byte) error
    ParseWebhook(body []byte) ([]Event, error)                          // normalized: payment.succeeded, payment.failed, subscription.renewed, subscription.canceled, refund.succeeded, ...
    CustomerPortalURL(ctx, CustomerRef) (string, error)                 // optional
}
```

A `fake` gateway implements every capability for tests and local development.

---

## File Map

Bearust SaaS (`bearust-saas`):
- Create: migrations `000024_billing_core`, `000025_billing_gateways`, `000026_webhook_events`.
- Create: `internal/billing/` — domain services (catalog, subscriptions state machine, invoicing, entitlements, dunning), handlers, jobs.
- Create: `internal/billing/providers/{fake,xendit,stripe,midtrans,duitku,paddle,dodo,paypal}/` with fixtures and a capability matrix README.
- Modify: `internal/org/` — limits read through `billing.Entitlements(org)`.
- Create: `src/frontend/src/app/(main)/app/billing/` — plan picker, checkout redirect, invoices, payment method, cancel.
- Create: `src/frontend/src/app/(main)/dashboard/billing/` — plans and prices, gateways, subscriptions, invoices, payments, refunds, webhook log.
- Modify: pricing page (marketing) to read plans and prices from the API.
- Modify: `docs/openapi.yaml`, README, `.env.example`, charts (public webhook URL, `BILLING_*` settings).

---

### Task 0: Provider research and capability matrix

- For each requested gateway, read current official docs and fill the matrix described under "Facts to verify". Note sandbox signup requirements and anything that needs a business account.
- Decide per gateway: `managed_by` (provider or saas), supported currencies for Bearust, and webhook events to consume.

**Validation:** the matrix is reviewed by the user before adapters beyond `fake` start.

- [ ] Capability matrix

### Task 1: Billing core

**Files:** migrations `000024`, `000025`, `000026`; `internal/billing/` (catalog, subscriptions, invoices, payments, entitlements); fake gateway.

- Subscription state machine with explicit transitions and tests for every edge (including out-of-order events).
- Entitlements: `Entitlements(org)` returns the effective plan limits; `internal/org`, `domains`, `lbconfig` read limits from it.
- Invoice numbering: per-year sequence, e.g. `BRT-2026-000123`, gapless within the database.

**Validation:** state machine table tests; Postgres tests for numbering under concurrency and for constraints; entitlements tests per status.

- [ ] Schema + catalog
- [ ] Subscription state machine + entitlements
- [ ] Invoices, payments, refunds (fake gateway)

### Task 2: Webhooks and jobs

- `POST /billing/webhooks/{gateway}` (public, no auth): verify → store → enqueue `billing.webhook` → 200. Invalid signatures answer 400 and are stored with `signature_valid = false` for staff review.
- Jobs: `billing.renewals` (daily: SaaS-managed subscriptions due in 7 days get an invoice and payment link; tokenized ones are charged on the due date), `billing.dunning` (reminders on day 1, 3, 6 of `past_due`; downgrade after grace), `billing.reconcile` (daily: compare provider state for provider-managed subscriptions and repair drift).

**Validation:** replay tests with recorded fixtures (duplicate, out-of-order, invalid signature); job tests with a fake clock.

- [ ] Webhook endpoint + processing
- [ ] Renewal, dunning, reconcile jobs

### Task 3: First real adapters (Xendit, Stripe by default)

- Implement against the capability matrix; sandbox credentials from env for live tests (`TEST_XENDIT_*`, `TEST_STRIPE_*`), skipped when absent.

**Validation:** adapter unit tests with recorded fixtures; live sandbox tests for checkout creation, webhook verification and refund.

- [ ] Xendit
- [ ] Stripe

### Task 4: Remaining adapters

- Midtrans, Duitku, Paddle, Dodo Payments, PayPal, in the order chosen in "Open decisions".
- Merchant of Record adapters store the provider invoice reference and skip SaaS tax lines.

**Validation:** as Task 3 per adapter.

- [ ] Midtrans
- [ ] Duitku
- [ ] Paddle
- [ ] Dodo Payments
- [ ] PayPal

### Task 5: Tenant billing UI

- `/app/billing` (`org.billing.read` to view, `org.billing.manage` to change): current plan and usage, plan picker with currency and interval, gateway choice limited to gateways enabled for that currency, checkout redirect and return page, invoices with download, cancel at period end, billing profile.

**Validation:** Vitest for plan/price selection and states; Playwright `billing-checkout.spec.ts` against the fake gateway (subscribe → webhook → limits raised → cancel → period end → Free).

- [ ] Billing pages
- [ ] E2E

### Task 6: Staff billing UI

- `/dashboard/billing` (`billing.read`/`billing.manage`, `plans.manage`): plans and prices, gateways (enable, sandbox/live, credentials, webhook URL to copy, test connection), subscriptions with manual actions (extend, cancel, change plan), invoices, payments and refunds, webhook log with replay.
- Pricing page reads plans and prices from the API.

**Validation:** Vitest; Playwright `billing-admin.spec.ts` (create a price, enable the fake gateway, refund a payment).

- [ ] Staff pages
- [ ] Pricing page

---

## Risks

- **Divergent gateway semantics:** recurring, refunds and webhooks differ widely. Mitigation: capability matrix first, normalized internal events, adapters never change entitlements directly.
- **Double charging and lost payments:** idempotency keys on every outbound call, unique provider ids, daily reconciliation.
- **Webhook spoofing:** mandatory signature verification; the endpoint never trusts payload amounts without matching an internal invoice.
- **Tax and legal:** non-MoR gateways make Bearust the seller; formal tax invoices and registration are outside this plan and need business input.
- **Credentials:** live keys encrypted at rest, sandbox and live separated per gateway, access limited to `billing.manage`.
- **Sandbox access:** some gateways require a registered business for sandbox or live keys; adapters without credentials are built against fixtures and marked unverified until tested.
