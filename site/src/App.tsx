import { useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BookOpen,
  Boxes,
  Braces,
  Check,
  Clipboard,
  Code2,
  Database,
  FileJson,
  FileText,
  Github,
  GitPullRequest,
  LockKeyhole,
  Network,
  Package,
  Radar,
  Scale,
  ShieldCheck,
  Sparkles,
  Terminal,
  Workflow,
} from 'lucide-react';
import HeroScene from './HeroScene';

const repoUrl = 'https://github.com/vmihalis/hacker-bob';
const npmUrl = 'https://www.npmjs.com/package/hacker-bob-cc';
const installCommand = 'npx -y hacker-bob-cc@latest install /path/to/your/project';

function externalProps(label: string) {
  return {
    target: '_blank',
    rel: 'noreferrer',
    'aria-label': label,
  };
}

function CommandBox() {
  const [copied, setCopied] = useState(false);

  const copyCommand = async () => {
    await navigator.clipboard.writeText(installCommand);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  return (
    <div className="command-box">
      <div className="command-box__bar">
        <span className="dot dot--red" />
        <span className="dot dot--yellow" />
        <span className="dot dot--green" />
      </div>
      <code>{installCommand}</code>
      <button type="button" className="icon-button" onClick={copyCommand} aria-label="Copy install command">
        {copied ? <Check size={18} /> : <Clipboard size={18} />}
      </button>
    </div>
  );
}

function App() {
  const architecture = [
    {
      icon: Workflow,
      title: 'Root orchestrator',
      text: 'Owns phase gates from recon through report and decides when hunter waves merge back.',
    },
    {
      icon: Database,
      title: 'MCP state',
      text: 'A project-local server keeps session state, coverage, findings, evidence readiness, and tool audit records coherent.',
    },
    {
      icon: FileJson,
      title: 'JSON artifacts',
      text: 'Handoffs, chain attempts, verification rounds, grade verdicts, and evidence packs stay machine-readable.',
    },
    {
      icon: Network,
      title: 'Parallel hunters',
      text: 'Specialized agents fan out by attack surface, then return structured findings instead of chat transcripts.',
    },
  ];

  const whyItWorks = [
    {
      icon: Boxes,
      title: 'Context stays bounded',
      text: 'Agents read the state they need and write compact handoffs, so long runs do not collapse into prompt soup.',
    },
    {
      icon: Braces,
      title: 'State is structured',
      text: 'Attack surfaces, coverage, auth profiles, findings, and dead ends are explicit artifacts, not memory.',
    },
    {
      icon: ShieldCheck,
      title: 'Verification has teeth',
      text: 'Findings go through skeptical, balanced, and final PoC passes before Bob treats them as reportable.',
    },
    {
      icon: BadgeCheck,
      title: 'Evidence drives grading',
      text: 'Evidence packs are required before grade and report work when final reportable findings exist.',
    },
    {
      icon: FileText,
      title: 'Reports ship with receipts',
      text: 'The final output is built for submission: PoCs, impact, evidence, and less speculative language.',
    },
  ];

  const openSource = [
    'Apache-2.0 license',
    'GitHub-first development',
    'Project-local installer',
    'Local session artifacts',
    'Contributor docs and release notes',
    'No hosted control plane',
  ];

  return (
    <div className="site-shell">
      <header className="site-header">
        <div className="site-header__inner">
          <a className="brand" href="#top" aria-label="Hacker Bob home">
            <img src="/brand/hacker-bob.png" alt="" />
            <span>Hacker Bob</span>
          </a>
          <nav className="nav-links" aria-label="Primary navigation">
            <a href="#install">Install</a>
            <a href="#architecture">Architecture</a>
            <a href="#safety">Safety</a>
          </nav>
          <a className="button button--ghost header-cta" href={repoUrl} {...externalProps('Open Hacker Bob on GitHub')}>
            <Github size={18} />
            GitHub
          </a>
        </div>
      </header>

      <main>
        <section className="hero" id="top">
          <HeroScene />
          <div className="hero__shade" />
          <div className="hero__inner">
            <div className="hero__copy">
              <p className="eyebrow">Apache-2.0 / local-first / Claude Code</p>
              <h1>Hacker Bob</h1>
              <p className="hero__subtitle">Open-source bug bounty workflow framework for Claude Code.</p>
              <p className="hero__body">
                Bob coordinates recon, auth capture, hunting, chaining, verification, grading, and report writing through
                local agents and a project-local MCP server.
              </p>
              <div className="hero__actions">
                <a className="button button--primary" href={repoUrl} {...externalProps('Star Hacker Bob on GitHub')}>
                  <Github size={19} />
                  Star on GitHub
                </a>
                <a className="button button--secondary" href="#install">
                  <Terminal size={19} />
                  Install Bob
                </a>
              </div>
              <dl className="hero__metrics" aria-label="Hacker Bob highlights">
                <div>
                  <dt>7</dt>
                  <dd>hunt phases</dd>
                </div>
                <div>
                  <dt>MCP</dt>
                  <dd>local state</dd>
                </div>
                <div>
                  <dt>OSS</dt>
                  <dd>Apache-2.0</dd>
                </div>
              </dl>
            </div>

            <aside className="hero-terminal" aria-label="Hacker Bob pipeline">
              <div className="hero-terminal__top">
                <span>bob run</span>
                <span>authorized target</span>
              </div>
              <ol>
                {['RECON', 'AUTH', 'HUNT', 'CHAIN', 'VERIFY', 'GRADE', 'REPORT'].map((stage, index) => (
                  <li key={stage}>
                    <span className="terminal-index">{String(index + 1).padStart(2, '0')}</span>
                    <span>{stage}</span>
                    <span className="terminal-pulse" />
                  </li>
                ))}
              </ol>
            </aside>
          </div>
        </section>

        <section className="install-strip section" id="install">
          <div className="section__inner install-strip__inner">
            <div>
              <p className="section-kicker">Install path</p>
              <h2>Install Bob into one Claude Code project.</h2>
              <p>
                The canonical npm package is <a href={npmUrl} {...externalProps('Open hacker-bob-cc on npm')}>hacker-bob-cc</a>.
                After install, restart Claude Code from that project and run <code>/bob-hunt target.com</code>.
              </p>
            </div>
            <div className="install-strip__command">
              <CommandBox />
              <div className="quick-facts" aria-label="Install facts">
                <span><Package size={16} /> npm: hacker-bob-cc</span>
                <span><Terminal size={16} /> requires Claude Code</span>
                <span><Code2 size={16} /> Node.js 20+</span>
              </div>
            </div>
          </div>
        </section>

        <section className="section architecture" id="architecture">
          <div className="section__inner">
            <div className="section-heading">
              <p className="section-kicker">Architecture</p>
              <h2>More than a prompt pack.</h2>
              <p>
                Bob is a coordinated agent runtime: the root orchestrator drives the pipeline, MCP state keeps the run
                durable, and hunter agents write artifacts the rest of the system can trust.
              </p>
            </div>

            <div className="pipeline-rail" aria-label="Bob hunt pipeline">
              {['RECON', 'AUTH', 'HUNT', 'CHAIN', 'VERIFY', 'GRADE', 'REPORT'].map((stage) => (
                <span key={stage}>{stage}</span>
              ))}
            </div>

            <div className="architecture-grid">
              {architecture.map(({ icon: Icon, title, text }) => (
                <article className="info-card" key={title}>
                  <Icon size={24} />
                  <h3>{title}</h3>
                  <p>{text}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="section why">
          <div className="section__inner">
            <div className="section-heading section-heading--wide">
              <p className="section-kicker">Why it works</p>
              <h2>Autonomy only matters when the system can keep its own score.</h2>
            </div>
            <div className="why-grid">
              {whyItWorks.map(({ icon: Icon, title, text }) => (
                <article className="info-card info-card--dense" key={title}>
                  <Icon size={22} />
                  <h3>{title}</h3>
                  <p>{text}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="section open-source">
          <div className="section__inner open-source__inner">
            <div>
              <p className="section-kicker">Open source</p>
              <h2>Transparent by default. Local by design.</h2>
              <p>
                Bob installs into your project, stores run artifacts locally, and keeps the control plane in code you can
                audit, fork, and patch.
              </p>
              <ul className="check-list">
                {openSource.map((item) => (
                  <li key={item}>
                    <Check size={17} />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <img src="/brand/hacker-bob-social.png" alt="Hacker Bob social preview artwork" />
          </div>
        </section>

        <section className="section safety" id="safety">
          <div className="section__inner safety__inner">
            <div>
              <p className="section-kicker section-kicker--warning">Safety</p>
              <h2>Authorized testing only.</h2>
              <p>
                Bob can send real requests, use local tools, attempt signup and authentication flows, and coordinate
                autonomous agents. Operators are responsible for scope, accounts, targets, rules of engagement, and any
                third-party systems involved.
              </p>
            </div>
            <div className="safety-grid">
              <article className="safety-item">
                <AlertTriangle size={22} />
                <h3>Explicit scope</h3>
                <p>Run Bob only against domains, applications, accounts, and infrastructure you are authorized to test.</p>
              </article>
              <article className="safety-item">
                <LockKeyhole size={22} />
                <h3>Local artifacts</h3>
                <p>Session state and evidence can contain sensitive target data and should be handled as security data.</p>
              </article>
              <article className="safety-item">
                <Scale size={22} />
                <h3>Operator judgment</h3>
                <p>Bob records activity for review, but it does not validate authorization or enforce every program rule.</p>
              </article>
            </div>
          </div>
        </section>

        <section className="section contributor">
          <div className="section__inner contributor__inner">
            <div>
              <p className="section-kicker">Contribute</p>
              <h2>Make Bob sharper.</h2>
              <p>
                File issues, read the docs, inspect the agent contracts, and help harden the hunting pipeline for the next
                release.
              </p>
            </div>
            <div className="contributor-links">
              <a className="button button--primary" href={repoUrl} {...externalProps('Open Hacker Bob repository')}>
                <Github size={18} />
                Repository
              </a>
              <a className="button button--secondary" href={`${repoUrl}/issues`} {...externalProps('Open Hacker Bob issues')}>
                <GitPullRequest size={18} />
                Issues
              </a>
              <a className="button button--ghost" href={`${repoUrl}#readme`} {...externalProps('Open Hacker Bob README')}>
                <BookOpen size={18} />
                README
              </a>
              <a className="button button--ghost" href={`${repoUrl}/tree/main/docs`} {...externalProps('Open Hacker Bob docs')}>
                <FileText size={18} />
                Docs
              </a>
              <a
                className="button button--ghost"
                href={`${repoUrl}/tree/main/docs/releases`}
                {...externalProps('Open Hacker Bob release notes')}
              >
                <Sparkles size={18} />
                Release notes
              </a>
            </div>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <div className="site-footer__inner">
          <span>Hacker Bob</span>
          <span>Open-source bug bounty workflow framework for Claude Code.</span>
          <a href={repoUrl} {...externalProps('Open Hacker Bob on GitHub')}>
            <Github size={16} />
            GitHub
          </a>
        </div>
      </footer>
    </div>
  );
}

export default App;
