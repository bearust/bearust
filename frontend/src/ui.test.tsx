// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { ThemeProvider } from './theme';
import { Alert, Button, Card, Field, ThemeSelect } from './ui';

function render(node: React.ReactNode) {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  act(() => root.render(node));
  return { container, root };
}

afterEach(() => { document.body.innerHTML = ''; });

describe('accessible Tailwind UI primitives', () => {
  it('associates Field labels, hints, and errors with the input', () => {
    const { container, root } = render(<Field id="email" label="Email address" hint="Use your work email" error="Email is required" />);
    const input = container.querySelector('input')!;
    expect(container.querySelector('label')?.htmlFor).toBe('email');
    expect(input.getAttribute('aria-describedby')).toContain('email-hint');
    expect(input.getAttribute('aria-describedby')).toContain('email-error');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    root.unmount();
  });

  it('provides disabled buttons with an accessible minimum target', () => {
    const { container, root } = render(<Button disabled>Save</Button>);
    const button = container.querySelector('button')!;
    expect(button.disabled).toBe(true);
    expect(button.className).toContain('min-h-11');
    root.unmount();
  });

  it('uses status roles and visible text for alert variants', () => {
    const { container, root } = render(<><Alert variant="success">Saved</Alert><Alert variant="danger">Failed</Alert></>);
    expect(container.querySelector('[role="status"]')?.textContent).toContain('Saved');
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Failed');
    root.unmount();
  });

  it('changes the persisted theme through ThemeSelect', () => {
    const { container, root } = render(<ThemeProvider><ThemeSelect /></ThemeProvider>);
    const select = container.querySelector('select')!;
    act(() => { select.value = 'dark'; select.dispatchEvent(new Event('change', { bubbles: true })); });
    expect(select.value).toBe('dark');
    root.unmount();
  });

  it('preserves a caller-provided ThemeSelect change handler', () => {
    let called = false;
    const { container, root } = render(<ThemeProvider><ThemeSelect onChange={() => { called = true; }} /></ThemeProvider>);
    const select = container.querySelector('select')!;
    act(() => { select.value = 'light'; select.dispatchEvent(new Event('change', { bubbles: true })); });
    expect(called).toBe(true);
    root.unmount();
  });

  it('renders Card as a semantic section', () => {
    const { container, root } = render(<Card aria-label="Summary">Content</Card>);
    expect(container.querySelector('section')?.textContent).toBe('Content');
    root.unmount();
  });
});
