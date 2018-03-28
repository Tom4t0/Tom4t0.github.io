---
layout: post
title: Attack Seam Framework
categories: vulnerability analysis
tags: [vulnerability analysis]
---
## 杂谈
最近在看一些JavaWeb的漏洞，Java各种库的相互用来用去就导致了很多漏洞能在不同的场景进行利用。其中seam framework就是一个例子(本文所指的seam framework都是seam2系列)。它是属于Jboss阵营，虽然现在已经不再维护了但是还是有不少站点是基于这个框架开发的。程序员使用seam框架能更快速的开发JSF类型的站点，其中seam framework使用了Mojarra，Mojarra是Oracle对JSF标准的实现，Jboss在MoJarra的基础上开发了richfaces。因为seam 所使用的基础库的版本较低，所以该框架存在很多安全问题，下面具体就分析了CVE-2010-1871 CVE-2013-2165 CVE-2013-3827 这几个安全漏洞的成因和官方的修复方案。
## CVE-2010-1871
此漏洞是一个表达式注入类型的漏洞影响2.2.1之前的版本，seam Framework基于EL表达式自己写了一套jboss expression language。然后在此表达式中可以通过反射的方法去实例化```java.lang.Runtime```等类，然后进一步执行任意命令。其调用方式为``` expressions.getClass().forName('java.lang.Runtime')```,若要执行命令的话通过反射的invoke方法就行，具体构造方式为``` expressions.getClass().forName('java.lang.Runtime').getDeclaredMethods()[19].invoke(expressions.getClass().forName('java.lang.R
untime').getDeclaredMethods()[7].invoke(null), 'command')```
其中需要注意的是```getDeclaredMethods```得到的方法位置可能因为系统的不同有所不同，笔者测试环境为MacOS。其中```getDeclaredMethods()[19]``` 与 ```getDeclaredMethods()[7]```分别为```getRuntime```与```exec``` 前面大概介绍了一下jboss expression language的利用方式，然后来具体看一下此次漏洞的成因。```org.jboss.seam.navigation.Pages``` 此类是用来处理seam中各个页面之间的行为的，具体行为的配置在/WEB-INF/pages.xml。在 ```preRender``` 方法中调用了 ```callAction```

```
   /**
    * Call the action requested by s:link or s:button.
    */
   private static boolean callAction(FacesContext facesContext)
   {
      //TODO: refactor with Pages.instance().callAction()!!
      
      boolean result = false;
      
      String outcome = facesContext.getExternalContext()
            .getRequestParameterMap().get("actionOutcome");
      String fromAction = outcome;
      
      if (outcome==null)
      {
         String actionId = facesContext.getExternalContext()
               .getRequestParameterMap().get("actionMethod");
         if (actionId!=null)
         {
            if ( !SafeActions.instance().isActionSafe(actionId) ) return result;
            String expression = SafeActions.toAction(actionId);
            result = true;
            MethodExpression actionExpression = Expressions.instance().createMethodExpression(expression);
            outcome = toString( actionExpression.invoke() );
            fromAction = expression;
            handleOutcome(facesContext, outcome, fromAction);
         }
      }
      else
      {
         handleOutcome(facesContext, outcome, fromAction);
      }
      
      return result;
   }
```
在http请求中获取```actionOutcome```后传入了```handleOutcome```在此调用了```facesContext.getApplication().getNavigationHandler().handleNavigation```其中handleNavigation是对JSF中```NavigationHandler```这个抽象类的实现，在```org.jboss.seam.jsf.seamNavigationHandler.handleNavigation```方法中进入了```FacesManager.instance().interpolateAndRedirect()```最后在此方法中的```Interpolator.instance().interpolate```进行了表达式的解析。测试如下图所示
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-27-15221387286515.jpg)
该漏洞后续修复方式为在actionOutcome中检查是否包含```#{```等字符来防止表达式注入。虽然这样是直接杜绝了在actionOutcome参数中进行表达式注入，但是我们注意下面的代码
```
if(outcome == null) {
                String actionId = (String)facesContext.getExternalContext().getRequestParameterMap().get("actionMethod");
                if (actionId != null) {
                    if (!SafeActions.instance().isActionSafe(actionId)) {
                        return result;
                    }

                    String expression = SafeActions.toAction(actionId);
                    result = true;
                    MethodExpression actionExpression = Expressions.instance().createMethodExpression(expression);
                    outcome = toString(actionExpression.invoke(new Object[0]));
                    handleOutcome(facesContext, outcome, expression);
                }
```

其中```actionId```在经过一系列检查之后还是生成了```expression```进入了```handleOutcome```方法中，来看看经过了一些什么检查。

```
    public boolean isActionSafe(String id) {
        if (this.safeActions.contains(id)) {
            return true;
        } else {
            int loc = id.indexOf(58);
            if (loc < 0) {
                throw new IllegalArgumentException("Invalid action method " + id);
            } else {
                String viewId = id.substring(0, loc);
                String action = "\"#{" + id.substring(loc + 1) + "}\"";
                InputStream is = FacesContext.getCurrentInstance().getExternalContext().getResourceAsStream(viewId);
                if (is == null) {
                    throw new IllegalStateException("Unable to read view /" + viewId + " to execute action " + action);
                } else {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is));

                    try {
                        while(true) {
                            boolean var7;
                            if (reader.ready()) {
                                if (!reader.readLine().contains(action)) {
                                    continue;
                                }

                                this.addSafeAction(id);
                                var7 = true;
                                return var7;
                            }

                            var7 = false;
                            return var7;
                        }
                    } catch (IOException var17) {
                        throw new RuntimeException("Error parsing view /" + viewId + " to execute action " + action, var17);
                    } finally {
                        try {
                            reader.close();
                        } catch (IOException var16) {
                            throw new RuntimeException(var16);
                        }
                    }
                }
            }
        }
    }

```
通过这个方法我们可以知道，如果利用```actionId```来进行表达式注入，那么我们需要有一个可以控制内容的资源文件，在这个资源文件中包含我们需要执行的EL表达式。例如在web目录存在一个/img/test.jpg的文件，里面包含你要执行的EL表达式，构造如下请求就能执行```/test.seam?actionMethod:test/test.jpg:EL表达式```。在hitcon 2016 的Angry seam题中就有一处利用。在template.xhtml中有如下代码

```
<script>
var NAME="#{util.escape(sessionScope['user'].getUsername())}";
var SID="#{util.escape(cookie['JSESSIONID'].value)}";
var DESC="#{util.escape(sessionScope['user'].getDescription())}";
</script>
```
其中DESC我们可以自己设置，首先将我们的DESC设置为```?x=#{expressions.instance().createValueExpression(request.getHeader('cmd')).getValue()}```其含义就是获取请求头中的cmd。然后在请求```template.seam?actionMethod=template.xhtml:util.escape(sessionScope['user'].getDescription())```通过前面的代码分析我们知道其实就是去执行```util.escape(sessionScope['user'].getDescription())```这个表达式，将此表达式执行的结果赋值给了```outname```，然后将```outname```传递给```handleOutcome```方法，又执行了一次表达式。所以这是一个EL表达式二次执行的问题。此处执行的表达式就是DESC设置的表达式，因为在DESC中通过表达式再次实例化了一个表达式执行的实例，所以cmd中的表达式得到执行。
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-28-15222283869796.jpg)


## CVE-2013-2165
seam框架在2.2.1版本时使用的richfaces的版本为3.3.3.Final，此版本存在一处Java反序列化漏洞。因此这个漏洞也直接影响seam框架，通过这个漏洞我们可以直接实现RCE。下面简单分析一下此漏洞，该漏洞核心源码是 org.ajax4jsf.resource.ResourceBuilderImpl

```
.....

private static final Pattern DATA_SEPARATOR_PATTERN = Pattern.compile("/DAT(A|B)/");

......

public Object getResourceDataForKey(String key) {
        Object data = null;
        String dataString = null;
        Matcher matcher = DATA_SEPARATOR_PATTERN.matcher(key);
        if (matcher.find()) {
            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("RESTORE_DATA_FROM_RESOURCE_URI_INFO", key, dataString));
            }

            int dataStart = matcher.end();
            dataString = key.substring(dataStart);
            byte[] objectArray = null;

            try {
                byte[] dataArray = dataString.getBytes("ISO-8859-1");
                objectArray = this.decrypt(dataArray);
            } catch (UnsupportedEncodingException var12) {
                ;
            }

            if ("B".equals(matcher.group(1))) {
                data = objectArray;
            } else {
                try {
                    ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(objectArray));
                    data = in.readObject();
                } catch (StreamCorruptedException var9) {
                    log.error(Messages.getMessage("STREAM_CORRUPTED_ERROR"), var9);
                } catch (IOException var10) {
                    log.error(Messages.getMessage("DESERIALIZE_DATA_INPUT_ERROR"), var10);
                } catch (ClassNotFoundException var11) {
                    log.error(Messages.getMessage("DATA_CLASS_NOT_FOUND_ERROR"), var11);
                }
            }
        }

        return data;
    }
```
这段代码很简单，就是将传递过来的key进行解密之后的数据传入了readObject方法从而导致RCE。那么问题是这个key是如何输入的呢？这就是涉及到richfaces这个库了。这个库会去处理在URL中以/a4j/开头的路径，当你请求http://test.com/a4j/xxx 之后，中间件会将/a4j/xxxx 传递给richfaces这个库去处理后面的数据。具体代码为
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-27-15221228205237.jpg)
继续构造

``` 
/a4j/g/3_3_3.Finalorg/richfaces/renderkit/html/scripts/skinning.js/DATA/xxxx 
```
这种格式的URL之后richfaces会将/a4j/a/3_3_3.Final先去除，这是个根据版本信息所产生的标识，然后找到org/richfaces/renderkit/html/scripts/skinning.js/此资源之后将后面的参数传入了getResourceDataForKey当中，然后/DATA/之后的数据经过一个decrypt方法之后就进入了readObject方法。其具体调用链如下:
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-27-15220710395443.jpg)
明白漏洞流程之后就可以直接通过ysoserial来进行RCE了。
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-27-15220712257975.jpg)
richfaces开发团队在richfaces3.3.4.Final对此漏洞进行了修复，修复方案是在反序列化时检测了类是否在白名单内。白名单文件在org.ajax4jsf.resource.resource-serialization.properties 大概看了一下似乎默认的这些类都无法利用起来。![](http://ogmho3r7t.bkt.clouddn.com/2018-03-27-15221303506179.jpg)


## CVE-2013-3827
这个path traversal是在Mojarra2.0-2.1.18之间都存在，由于seam Framework 2.3.1 Final中Mojarra版本为2.1.7，所以存在此漏洞。但是seam Framework 2.2.1 Final使用的是Mojarra1.2.12所以不存在此漏洞。在分析漏洞成因之前需要了解一下seam框架的处理流程，通常在web.xml中能看到如下配置

```
	<filter>
		<filter-name>seam Filter</filter-name>
		<filter-class>org.jboss.seam.servlet.seamFilter</filter-class>
	</filter>
	<filter-mapping>
		<filter-name>seam Filter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
	<servlet>
		<servlet-name>seam Resource Servlet</servlet-name>
		<servlet-class>org.jboss.seam.servlet.seamResourceServlet</servlet-class>
	</servlet>
	<servlet-mapping>
		<servlet-name>seam Resource Servlet</servlet-name>
		<url-pattern>/resource/*</url-pattern>
	</servlet-mapping>
	<servlet>
		<servlet-name>Faces Servlet</servlet-name>
		<servlet-class>javax.faces.webapp.FacesServlet</servlet-class>
		<load-on-startup>1</load-on-startup>
	</servlet>
	<servlet-mapping>
		<servlet-name>Faces Servlet</servlet-name>
		<url-pattern>*.seam</url-pattern>
	</servlet-mapping>
```
当一个请求为 http://target.com/javax.faces.resource/xxxx 时，首先要经过 seam Filter的判断，只有在seam框架内部的filter处理完成之后才会将对应的请求发送给Mojarra处理。下面这张调用栈的图就很好的展示了整个流程
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-28-15222171907906.jpg)
漏洞的触发点是在Mojarra对资源文件请求的处理过程，其中```com.sun.faces.application.resource.WebappResourceHelper.findResource```是处理资源路径的关键方法，在此方法中完成了路径的拼接。

```
  if (library != null) {
            basePath = library.getPath() + '/' + resourceName;
        } else {
            if (localePrefix == null) {
                basePath = getBaseResourcePath() + '/' + resourceName;
            } else {
                basePath = getBaseResourcePath()
                           + '/'
                           + localePrefix
                           + '/'
                           + resourceName;
            }
        }
```
我们传递的resourceName通过下面的代码所获取到

```
String resourceId = normalizeResourceRequest(context);
        // handleResourceRequest called for a non-resource request,
        // bail out.
        if (resourceId == null) {
            return;
        }
        
        ExternalContext extContext = context.getExternalContext();

        if (isExcluded(resourceId)) {
            extContext.setResponseStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        assert (null != resourceId);
        assert (resourceId.startsWith(RESOURCE_IDENTIFIER));

        Resource resource = null;
        String resourceName = null;
        String libraryName = null;
        if (ResourceHandler.RESOURCE_IDENTIFIER.length() < resourceId.length()) {
            resourceName = resourceId.substring(RESOURCE_IDENTIFIER.length() + 1);
            assert(resourceName != null);
            libraryName = context.getExternalContext().getRequestParameterMap()
                  .get("ln");
            resource = context.getApplication().getResourceHandler().createResource(resourceName, libraryName);
        }
```
这段代码中先是得到resourceId的值为```/javax.faces.resource/xxxx```，再判断了资源文件类型，默认情况下以下几种类型的文件是无法访问
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-28-15222182213175.jpg)
所以该漏洞默认情况下是无法读取以上几种文件的内容。```resourceName```通过```resourceName = resourceId.substring(RESOURCE_IDENTIFIER.length() + 1)```赋值，若我们将请求设置为 http://target.com/javax.faces.resource.../WEB-INF/web.xml.seam 那么```resourceName```就为```../WEB-INF/web.xml```了。再通过后面```findResource```方法的拼接最后```basepath```的值就为```/resources/../WEB-INF/web.xml```因而成功读取到web.xml里面的数据了。
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-28-15222200461324.jpg)
除此之外还有另外一种利用方式，其实过程也大同小异。就是利用```libraryName``` 来进行跳目录，其赋值方式为```libraryName=context.getExternalContext().getRequestParameterMap().get("ln");```将请求的URL改为 ```http://target.com/javax.faces.resource/javax.faces.resource./WEB-INF/web.xml.seam?ln=..``` 然后basepath通过```basePath = library.getPath() + '/' + resourceName;```赋值为```/resources/../WEB-INF/web.xml```也一样读取到了web.xml的内容了。
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-28-15222206254018.jpg)
其实在第二种利用方式中，程序本身检查通过```libraryNameContainsForbiddenSequence```检测了```libraryName```的值，但是黑名单字符中不包含``..`` 官方在后面的修复方案就是将```..```加入黑名单并且同时检查了```resourceName```和```libraryName```是否合法。
![](http://ogmho3r7t.bkt.clouddn.com/2018-03-28-15222210619941.jpg)

## 参考
[cve-2010-1871-jboss-seam-framework](http://blog.o0o.nu/2010/07/cve-2010-1871-jboss-seam-framework.html)

[HITCON 2016 WEB WRITEUP](http://www.melodia.pw/?p=743
)

[My-CTF-Web-Challenges](https://github.com/orangetw/My-CTF-Web-Challenges/
)

[web500-hitconctf-2016-and-exploit-cve-2013-2165](http://vnprogramming.com/index.php/2016/10/10/web500-hitconctf-2016-and-exploit-cve-2013-2165/
)

[path-traversal-defects-oracles-jsf2-implementation](https://www.synopsys.com/blogs/software-security/path-traversal-defects-oracles-jsf2-implementation/
)


