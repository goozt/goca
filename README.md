# goca
A go api server to share certificates


## Docker

```sh
docker build -t goca:local .
docker run --rm -p "8000:8000" -v rooCA:/.rootCA goca:local
```

## Development

```
sudo sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/bin
task init
task ready
task
```