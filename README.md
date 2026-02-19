# NodeCtl

> 一个轻量、高效的个人订阅节点管理工具。

## 📖 项目简介
NodeCtl 旨在提供一个简洁直观的界面和稳定安全的后台，帮助你集中管理自建节点和机场订阅、通过默认参数的优化在保证设置不过于复杂的前提下即直观，同时拥有极高自定义能力。

## 特点
1、内置模板基于链式代理，无感替换节点的链路位置

2、内置节点一键安装脚本，部署节点仅需复制命令即可自动回传链接到面板

3、支持机场订阅加入到自建订阅，实现通过机场节点中转或者落地。

4、安全性，所有代码开源，在声明本项目后可随意修改发布。

## 🎨 演示 (Demo)

https://demo.hobin.net/

账号admin 密码admin

## 🚀 快速部署

我们推荐使用 Docker 进行部署，这是最简单、最快捷且保持环境干净的方式。

### 方式一：Docker Run (快捷命令)

你可以直接运行以下命令拉取并启动容器：


```bash
docker run -d \
  --name nodectl-demo \
  --restart unless-stopped \
  -p 7878:8080 \
  -v /opt/1panel/apps/nodectl-demo:/app/data \
  ghcr.io/hobin66/nodectl:latest
```

### 文档说明

内置安装脚本位于internal\service\singbox.tpl，如想替换内置脚本进行测试可以在/data/debug目录新建同名文件，将会优先使用该处模板。


### 声明：

1、本项目引用了许多开源工具，包括但不限于内置安装脚本。内置模板，内置路由规则组，及各种开源工具，在这里表示感谢。

2、本项目所有代码及构建流程都在githun开源，欢迎审查。

内置安装脚本修改自 https://github.com/caigouzi121380/singbox-deploy 
