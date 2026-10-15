import { MoodNav } from '@/components/brand/MoodNav';
import { MoodHero } from '@/components/brand/MoodHero';
import { MoodCard } from '@/components/brand/MoodCard';

export default function BrandPage() {
  return (
    <main>
      <MoodNav />
      <MoodHero
        title="Authorized. Measured. Validated."
        subtitle="Vorsyghta’s industrial control-room brand, rebuilt around the Futuristic Megastructures moodboard and hero video. Orange primary, cyan signal, steel canvas."
        ctaLabel="Start Trial"
        ctaHref="#start"
        videoSrc="/videos/hero.mp4"
        backgroundImage="/backgrounds/control-room.jpg"
      />
      <section className="page-width" style={{ padding: '4rem 2rem' }}>
        <h2 style={{ fontSize: '2rem', marginBottom: '2rem' }}>Brand System</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px,1fr))', gap: '1.5rem' }}>
          <MoodCard title="Primary Action" value="Orange #ff7a1a" sub="CTAs, highlights" status="good" accent="orange" />
          <MoodCard title="Signal Cyan" value="#2bbfd7" sub="Provenance, chips" status="idle" accent="cyan" />
          <MoodCard title="Midnight Canvas" value="#0b0f14" sub="Marketing background" status="idle" accent="steel" />
          <MoodCard title="Warm Paper" value="#f5f3f0" sub="Transactional surfaces" status="idle" accent="orange" />
          <MoodCard title="Steel Border" value="#2c3e50" sub="Card hairlines" status="idle" accent="steel" />
          <MoodCard title="Control Room" value="Moodboard crop" sub="Dashboard texture" status="warn" accent="cyan" />
        </div>
        <div style={{ marginTop: '3rem', padding: '2rem', background: 'var(--paper)', border: '1px solid var(--hairline-dark)', borderRadius: '12px' }}>
          <h3 style={{ marginTop: 0 }}>Usage</h3>
          <ul>
            <li>Hero uses video + grid overlay with orange CTA.</li>
            <li>Data panels use MoodCard with steel accent bar.</li>
            <li>Nav is sticky midnight with blur and orange primary button.</li>
            <li>Backgrounds from /public/backgrounds/ are used as section textures, not full bleed photos.</li>
          </ul>
        </div>
      </section>
    </main>
  );
}
