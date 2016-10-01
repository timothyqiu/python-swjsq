**********************************
python-swjsq: 迅雷快鸟命令行客户端
**********************************

python-swjsq 是基于 `Xunlei-FastDick <https://github.com/fffonion/Xunlei-Fastdick>`_ 的迅雷快鸟命令行客户端。

基于原版，以以下这些为目标，希望做到更好：

* 专注做一件事
* 更好的接口
* Pythonic


====
安装
====

python-swjsq 使用 pip 安装：

.. code-block:: bash

    pip install swjsq


====
使用
====

用以下两种方法之一提供登录凭据：

1. 新建 ``swjsq.account.txt`` 文件，将内容填写为 ``用户名,密码`` 即可。
2. 设置环境变量 ``XUNLEI_UID`` 为用户名，``XUNLEI_PASSWD`` 为密码。

使用时只需运行：

.. code-block:: bash

    swjsq

首次登录成功后， ``swjsq.account.txt`` 将被删除，加密后的用户名密码将被保存至 ``.swjsq.account`` 文件中。
