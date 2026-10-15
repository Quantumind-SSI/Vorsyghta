'use client';
import React from 'react';

type MoodHeroProps = {
  title: string;
  subtitle?: string;
  ctaLabel?: string;
  ctaHref?: string;
  videoSrc?: string;
  backgroundImage?: string;
};

export function MoodHero({
  title,
  subtitle,
  ctaLabel = 'Explore',
  ctaHref = '#',
  videoSrc = '/videos/hero.mp4',
  backgroundImage
}: MoodHeroProps) {
  return (
    <section className="mood-hero" aria-label="Brand hero">
      <div className="mood-hero__media">
        {videoSrc && (
          <video autoPlay muted loop playsInline className="mood-hero__video">
            <source src={videoSrc} type="video/mp4" />
          </video>
        )}
        {backgroundImage && <img src={backgroundImage} alt="" className="mood-hero__image" aria-hidden />}
        <div className="mood-hero__overlay" />
        <div className="mood-hero__grid" />
      </div>
      <div className="mood-hero__content">
        <span className="eyebrow">VORSYHTA</span>
        <h1>{title}</h1>
        {subtitle && <p className="mood-hero__subtitle">{subtitle}</p>}
        <div className="mood-hero__actions">
          <a href={ctaHref} className="button button--primary">{ctaLabel}</a>
          <a href="#learn" className="button button--inverted">Learn more</a>
        </div>
      </div>
      <style jsx>{`
        .mood-hero {
          position: relative;
          min-height: 78vh;
          display: grid;
          place-items: center;
          overflow: hidden;
          background: var(--midnight);
          color: var(--white);
        }
        .mood-hero__media {
          position: absolute;
          inset: 0;
        }
        .mood-hero__video,
        .mood-hero__image {
          width: 100%;
          height: 100%;
          object-fit: cover;
          filter: brightness(0.55) contrast(1.05);
        }
        .mood-hero__overlay {
          position: absolute;
          inset: 0;
          background: linear-gradient(100deg, rgba(11,15,20,0.85) 10%, rgba(11,15,20,0.45) 60%, rgba(11,15,20,0.9) 100%);
        }
        .mood-hero__grid {
          position: absolute;
          inset: 0;
          background-image: linear-gradient(var(--hairline-dark) 1px, transparent 1px), linear-gradient(90deg, var(--hairline-dark) 1px, transparent 1px);
          background-size: 48px 48px;
          opacity: 0.18;
          mix-blend-mode: overlay;
          pointer-events: none;
        }
        .mood-hero__content {
          position: relative;
          z-index: 2;
          max-width: 900px;
          padding: 4rem 2rem;
          text-align: left;
        }
        .mood-hero__content .eyebrow {
          color: var(--lime);
          letter-spacing: 0.18em;
          text-transform: uppercase;
          font-size: 0.75rem;
          margin-bottom: 1rem;
          display: inline-block;
        }
        .mood-hero__content h1 {
          font-size: clamp(2.5rem, 6vw, 4.5rem);
          line-height: 1.05;
          margin: 0 0 1rem;
          font-weight: 800;
          letter-spacing: -0.02em;
        }
        .mood-hero__subtitle {
          color: var(--violet-soft);
          font-size: 1.125rem;
          max-width: 60ch;
          margin: 0 0 2rem;
        }
        .mood-hero__actions {
          display: flex;
          gap: 1rem;
          flex-wrap: wrap;
        }
        .button--primary {
          background: var(--lime);
          color: var(--midnight);
          font-weight: 800;
          text-transform: uppercase;
          padding: 0.9rem 1.5rem;
          border-radius: 8px;
          text-decoration: none;
        }
        .button--inverted {
          background: transparent;
          color: var(--white);
          border: 1px solid var(--hairline-dark);
          padding: 0.9rem 1.5rem;
          border-radius: 8px;
          text-decoration: none;
          text-transform: uppercase;
          font-weight: 700;
        }
      `}</style>
    </section>
  );
}
