FROM nginx:alpine

# Install required DNS tools
RUN apk add --no-cache bind-tools

# Keep the rest of nginx:alpine defaults
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]