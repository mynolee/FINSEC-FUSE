FROM nginxinc/nginx-unprivileged:1.28-alpine
COPY ingress/nginx.conf /etc/nginx/nginx.conf
USER 101:101
EXPOSE 8080 8081
ENTRYPOINT ["nginx", "-g", "daemon off;"]

CMD []
