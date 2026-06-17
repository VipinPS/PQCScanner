import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import styles from './index.module.css';

const features = [
  {
    title: 'Multi-Language Scanning',
    description:
      'Detect quantum-vulnerable cryptography across 15+ languages. Scans source code, dependencies, secrets, and binary artifacts for 26+ crypto patterns.',
  },
  {
    title: 'CBOM Compliance',
    description:
      'Export Cryptography Bill of Materials in CycloneDX 1.5 format. Track every cryptographic asset, assess crypto agility from L1 to L5, and satisfy compliance requirements.',
  },
  {
    title: 'AI-Powered FP Reduction',
    description:
      'Minimize noise with path-based exclusions, call-graph reachability analysis, and Ollama-backed AI validation. Focus on real findings, not false alarms.',
  },
];

function HeroSection() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx('hero', styles.heroBanner)}>
      <div className="container">
        <h1 className={styles.heroTitle}>{siteConfig.title}</h1>
        <p className={styles.heroSubtitle}>{siteConfig.tagline}</p>
        <div className={styles.heroButtons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/intro"
          >
            Get Started
          </Link>
          <Link
            className="button button--secondary button--lg"
            href="https://github.com/VipinPS/PQCScanner"
          >
            GitHub
          </Link>
        </div>
      </div>
    </header>
  );
}

function FeatureCard({ title, description }) {
  return (
    <div className={clsx('col col--4', styles.featureCard)}>
      <div className="padding-horiz--md padding-vert--lg">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

function FeaturesSection() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {features.map((props, idx) => (
            <FeatureCard key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description={siteConfig.tagline}
    >
      <HeroSection />
      <main>
        <FeaturesSection />
      </main>
    </Layout>
  );
}
