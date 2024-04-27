FROM traefik

ARG PLUGIN_MODULE=github.com/RouNNdeL/tmp-auth-proxy
WORKDIR /app

ADD . ./plugins-local/src/${PLUGIN_MODULE}
