import Link from "next/link";

const STEPS: ReadonlyArray<{ n: number; label: string; route: string }> = [
  { n: 1, label: "Organization", route: "/onboarding/profile" },
  { n: 2, label: "Use cases", route: "/onboarding/use-cases" },
  { n: 3, label: "Environments", route: "/onboarding/environments" },
  { n: 4, label: "Review & activate", route: "/onboarding/review" },
];

export function OnboardingStepNav({ current }: { current: number }) {
  return (
    <nav className="onboarding-stepnav" aria-label="Onboarding progress">
      <ol>
        {STEPS.map((step) => (
          <li
            key={step.n}
            className={step.n === current ? "onboarding-stepnav__item onboarding-stepnav__item--current" : "onboarding-stepnav__item"}
            aria-current={step.n === current ? "step" : undefined}
          >
            {step.n < current ? (
              <Link href={step.route}><span className="stepnav-num">✓</span> {step.label}</Link>
            ) : (
              <span><span className="stepnav-num">{step.n}</span> {step.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
