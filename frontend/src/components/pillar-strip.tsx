import { ValidateIcon, SimulateIcon, ResearchIcon, IntelligenceIcon, ComplianceIcon } from './icons/pillars';

const pillars = [
  { name: 'Validate', Icon: ValidateIcon },
  { name: 'Simulate', Icon: SimulateIcon },
  { name: 'Research', Icon: ResearchIcon },
  { name: 'Intelligence', Icon: IntelligenceIcon },
  { name: 'Compliance', Icon: ComplianceIcon },
];

export function PillarStrip() {
  return (
    <div className="principle-strip">
      <div className="page-width principle-strip__inner">
        {pillars.map(p => (
          <span key={p.name} className="flex items-center justify-center gap-2">
            <p.Icon />
            {p.name}
          </span>
        ))}
      </div>
    </div>
  );
}
