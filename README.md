# 迅雷快鸟

基于 [Xunlei-FastDick](https://github.com/fffonion/Xunlei-Fastdick) 的迅雷快鸟命令行客户端。

# 快速入门

* 同目录下新建 __swjsq.account.txt__，填入`用户名,密码`，如`ahaha,123456`（英文逗号），并保存
* `python -m swjsq &`

# 说明

* 生成的`swjsq_wget.sh`和`swjsq_0.0.1_all.ipk`包含了账户信息，请不要共享给他人使用
* 明文存储的密码将会在第一次登陆成功后保存为数字ID和密码的MD5，明文文件将会删除。如果需要更换账号，只需新建一个 __swjsq.account.txt__，并重新运行python脚本
* 如果修改或更新了python脚本，下次运行时将重新生成ipk包和`swjsq_wget.sh`，请重新安装ipk或拷贝`swjsq_wget.sh`到路由器
* 会员权限及月加速流量等详见[这里](http://swjsq.xunlei.com)
* 自带[这里抄的](https://github.com/mengskysama/XunLeiCrystalMinesMakeDie/blob/master/run.py)纯python实现RSA加密，可选安装pycrypto加快(首次)运算速度
