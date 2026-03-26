# goca
A go api server to share certificates


## Docker

```sh
docker build -t goca:local .
docker run --rm -p "8000:8000" -v ./.certs:/.ca -v rooCA:/.rootCA goca:local
```