import tailwindcss from '@tailwindcss/postcss';
import autoprefixer from 'autoprefixer';

export default {
  plugins: [
    {
      postcssPlugin: 'inject-tailwind-config',
      Once(root) {
        // Inject @config to avoid IDE warnings in index.css
        const hasConfig = root.some(node => node.type === 'atrule' && node.name === 'config');
        if (!hasConfig) {
          root.prepend({ name: 'config', params: '"../tailwind.config.js"' });
        }
      }
    },
    tailwindcss(),
    autoprefixer(),
  ],
}
