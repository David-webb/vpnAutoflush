## ubuntu14.04 Network-Manager VPN批量添加账号的脚本
1. 程序流程: 

    + 先爬取vpn信息主页（主页内容是文本）
    + 解析文本文件，将其结构化，将其中的代理网关ip按照"PPTP-L2TP", "PPTP"等分类
    + 保存一份VPN配置文件的模板到本地，将上述网关ip组装成配置文件放到指定目录(/etc/NetworkManager/system-connections/)下
    + 修改文件的权限为600, 然后重启NM服务，就可以在系统右上角的vpn列表中看见添加的账号

2. 程序的使用: 

    + 脚本需要三个参数vpn的账户名和密码，以及主机的root密码(写文件到系统目录需要root权限) 
    
            python vpnFresh.py vpn_username vpn_pwd host_root_pwd

    + 需要改进: 将root密码的输入设成可选，可以让用户以root身份运行程序，这样避免root密码泄露的风险

    
