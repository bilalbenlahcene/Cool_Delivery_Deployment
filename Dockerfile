# Use a lightweight HTTP server
FROM nginx:alpine

# Copy the static website content
COPY website/ /usr/share/nginx/html/

# Expose HTTP port
EXPOSE 80

# Start NGINX server
CMD ["nginx", "-g", "daemon off;"]
