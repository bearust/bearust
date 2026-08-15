import type { SVGProps } from "react";

/**
 * Line icons for sidebar/navbar chrome, one consistent stroke weight (1.5px,
 * round joins) matching the Signal Board instrument-panel grammar. Drawn,
 * not glyphs or emoji.
 */

const base: SVGProps<SVGSVGElement> = {
  viewBox: "0 0 20 20",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};

export function IconRoute(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <circle cx="4.5" cy="5" r="2" />
      <circle cx="15.5" cy="15" r="2" />
      <path d="M4.5 7v2a3 3 0 0 0 3 3h5a3 3 0 0 1 3 3" />
    </svg>
  );
}

export function IconAdvisor(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <path d="M10 2.5l1.6 3.6 3.9.5-2.9 2.7.8 3.9L10 11.4l-3.4 1.8.8-3.9-2.9-2.7 3.9-.5z" />
      <path d="M10 15.5v2" />
    </svg>
  );
}

export function IconShield(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <path d="M10 2.5l6 2.2v4.6c0 4-2.6 6.8-6 8.2-3.4-1.4-6-4.2-6-8.2V4.7z" />
      <path d="M7.3 10l1.9 1.9 3.5-3.8" />
    </svg>
  );
}

export function IconChart(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <path d="M3 17V3" />
      <path d="M3 17h14" />
      <path d="M6.5 14v-3.5" />
      <path d="M10.5 14V6" />
      <path d="M14.5 14v-6" />
    </svg>
  );
}

export function IconUsers(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <circle cx="7" cy="6.5" r="2.5" />
      <path d="M2.5 16v-.8A4.2 4.2 0 0 1 7 11a4.2 4.2 0 0 1 4.5 4.2v.8" />
      <path d="M12.5 5.3a2.5 2.5 0 0 1 0 4.9" />
      <path d="M13.8 11.2A4.2 4.2 0 0 1 17.5 15.2v.8" />
    </svg>
  );
}

export function IconAudit(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <rect x="4" y="2.5" width="12" height="15" rx="1" />
      <path d="M7 7h6" />
      <path d="M7 10.2h6" />
      <path d="M7 13.4h3.5" />
    </svg>
  );
}

export function IconMenu(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <path d="M3 5.5h14" />
      <path d="M3 10h14" />
      <path d="M3 14.5h14" />
    </svg>
  );
}

export function IconClose(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <path d="M5 5l10 10" />
      <path d="M15 5L5 15" />
    </svg>
  );
}

export function IconChevronDown(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <path d="M5 7.5l5 5 5-5" />
    </svg>
  );
}

export function IconUserCircle(props: SVGProps<SVGSVGElement>) {
  return (
    <svg {...base} {...props}>
      <circle cx="10" cy="10" r="7.5" />
      <circle cx="10" cy="8" r="2.4" />
      <path d="M4.8 15.4a5.6 5.6 0 0 1 10.4 0" />
    </svg>
  );
}
