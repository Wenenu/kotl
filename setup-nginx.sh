#!/bin/bash

# Quick nginx config setup script
# Run with: sudo bash setup-nginx.sh

cat > /etc/nginx/sites-available/webpanel << 'EOF'
server {
    listen 80;
    server_name 62.60.179.121;

    # Increase client body size for large uploads
    client_max_body_size 50M;

    # Proxy all requests to Node.js server
    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

echo "Nginx configuration created at /etc/nginx/sites-available/webpanel"
echo "Next steps:"
echo "1. Enable the site: sudo ln -s /etc/nginx/sites-available/webpanel /etc/nginx/sites-enabled/"
echo "2. Test configuration: sudo nginx -t"
echo "3. Restart nginx: sudo systemctl restart nginx"

