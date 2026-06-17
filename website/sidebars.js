/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      items: ['intro'],
      collapsed: false,
    },
    {
      type: 'category',
      label: 'Features',
      items: [
        'features/scanning',
        'features/cbom',
        'features/false-positive-reduction',
      ],
    },
    {
      type: 'category',
      label: 'Architecture',
      items: ['architecture'],
    },
    {
      type: 'category',
      label: 'API Reference',
      items: [],
      link: {
        type: 'generated-index',
        title: 'API Reference',
        description: 'REST API documentation for PQCScanner (68 endpoints).',
      },
    },
    {
      type: 'category',
      label: 'Contributing',
      items: [],
      link: {
        type: 'generated-index',
        title: 'Contributing',
        description: 'Guidelines for contributing to PQCScanner.',
      },
    },
  ],
};

module.exports = sidebars;
