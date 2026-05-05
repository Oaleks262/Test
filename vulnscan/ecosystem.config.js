// PM2 Ecosystem — конфігурація запуску VULNSCAN
module.exports = {
  apps: [
    {
      name: 'vulnscan',
      script: 'server.js',
      cwd: '/var/www/vulnscan',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '256M',
      env: {
        NODE_ENV: 'production',
        PORT: 3001,
      },
      error_file: '/var/log/pm2/vulnscan-error.log',
      out_file: '/var/log/pm2/vulnscan-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
    },
  ],
};
