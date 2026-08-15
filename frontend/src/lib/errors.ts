import type { ApiError } from "../api";
import { i18n } from "../i18n";

export const SERVER_ERROR_KEYS: Record<string, string> = {
  invalid_credentials: "errors.authInvalidCredentials",
  rate_limited: "errors.authRateLimited",
  invalid_setup_token: "errors.authInvalidSetupToken",
  already_initialized: "errors.authAlreadyInitialized",
  unauthorized: "errors.unauthorized",
  forbidden: "errors.forbidden",
  invalid_input: "errors.invalidInput",
  not_found: "errors.notFound",
  conflict: "errors.conflict",
  duplicate_domain: "errors.duplicateDomain",
  duplicate_email: "errors.duplicateEmail",
  last_admin: "errors.lastAdmin",
  self_mutation: "errors.selfMutation",
};

export const SERVER_MESSAGE_KEYS: Record<string, string> = {
  "Invalid email or password": "errors.authInvalidCredentials",
  "Too many authentication attempts": "errors.authRateLimited",
  "Invalid setup token": "errors.authInvalidSetupToken",
  "Setup has already completed": "errors.authAlreadyInitialized",
  "Authentication required": "errors.unauthorized",
  "Invalid locale": "errors.invalidInput",
};

export type ErrorDetails = Pick<Partial<ApiError>, "code" | "status"> & { message?: string };

export function errorDetails(error: unknown): ErrorDetails {
  if (!error || typeof error !== "object") return {};
  const candidate = error as { code?: unknown; status?: unknown; message?: unknown };
  return {
    code: typeof candidate.code === "string" ? candidate.code : undefined,
    status: typeof candidate.status === "number" ? candidate.status : undefined,
    message: typeof candidate.message === "string" ? candidate.message : undefined,
  };
}

export function serverErrorKey(error: unknown): string | undefined {
  const { code, message } = errorDetails(error);
  return (code && SERVER_ERROR_KEYS[code]) || (message && SERVER_MESSAGE_KEYS[message]);
}

export const sanitizeError = (error: unknown) =>
  i18n.t(serverErrorKey(error) ?? "errors.generic");
