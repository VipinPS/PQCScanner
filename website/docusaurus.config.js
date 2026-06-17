// @ts-check

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'PQCScanner',
  tagline: 'Find and fix quantum-vulnerable cryptography before Q-Day',
  favicon: 'img/logo.svg',

  url: 'https://VipinPS.github.io',
  baseUrl: '/PQCScanner/',

  organizationName: 'VipinPS',
  projectName: 'PQCScanner',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/VipinPS/PQCScanner/tree/main/website/',
        },
        blog: {
          showReadingTime: true,
          editUrl: 'https://github.com/VipinPS/PQCScanner/tree/main/website/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: 'dark',
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'PQCScanner',
        logo: {
          alt: 'PQCScanner Logo',
          src: 'img/logo.svg',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docsSidebar',
            position: 'left',
            label: 'Docs',
          },
          { to: '/blog', label: 'Blog', position: 'left' },
          {
            href: 'https://github.com/VipinPS/PQCScanner',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Documentation',
            items: [
              {
                label: 'Getting Started',
                to: '/docs/intro',
              },
              {
                label: 'Architecture',
                to: '/docs/architecture',
              },
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/VipinPS/PQCScanner',
              },
              {
                label: 'Issues',
                href: 'https://github.com/VipinPS/PQCScanner/issues',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              },
              {
                label: 'Contributing',
                href: 'https://github.com/VipinPS/PQCScanner/blob/main/CONTRIBUTING.md',
              },
            ],
          },
        ],
        copyright: `Copyright ${new Date().getFullYear()} PQCScanner Contributors. Built with Docusaurus.`,
      },
      prism: {
        theme: require('prism-react-renderer').themes.github,
        darkTheme: require('prism-react-renderer').themes.dracula,
        additionalLanguages: ['bash', 'yaml', 'json', 'python'],
      },
    }),
};

module.exports = config;
