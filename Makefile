# ProtoViz のビルド・デプロイ
#   make        … イメージをビルドしてローカルレジストリへ push し、Helm でデプロイ
#   make check  … 全パケットを組み立てて、長さ・チェックサム・DER 構造を検証
#   make serve  … k8s を使わずに手元で確認 (http://localhost:8000/)
VERSION   := $(shell sed -n 's/^appVersion: "\(.*\)"/\1/p' chart/protoviz/Chart.yaml)
REGISTRY  ?= localhost:5000
IMAGE     := $(REGISTRY)/protoviz:$(VERSION)
NAMESPACE ?= protoviz
export KUBECONFIG ?= $(HOME)/.kube/config

.PHONY: all image push deploy check serve status uninstall

all: push deploy

image: check
	docker build -t $(IMAGE) .

push: image
	docker push $(IMAGE)

deploy:
	helm lint chart/protoviz
	helm upgrade --install protoviz chart/protoviz -n $(NAMESPACE) --create-namespace \
	  --set image.repository=$(REGISTRY)/protoviz --set image.pullPolicy=Always --wait
	kubectl -n $(NAMESPACE) rollout restart deploy/protoviz
	kubectl -n $(NAMESPACE) rollout status deploy/protoviz

check:
	node tools/dump_packets.js site | python3 tools/verify_packets.py /dev/stdin

serve:
	cd site && python3 -m http.server 8000 --bind 127.0.0.1

status:
	kubectl -n $(NAMESPACE) get pods,svc,ingress

uninstall:
	helm uninstall protoviz -n $(NAMESPACE)
