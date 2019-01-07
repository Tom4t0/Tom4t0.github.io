---
layout: post
title: JNDI Injection Bypass
categories: tricks
tags: [tricks,java]
---

#### 背景

Oracle在jdk8u121之后设置了com.sun.jndi.rmi.object.trustURLCodebase为 false，限制了 RMI 利用方式中从远程加载 Class
com.sun.jndi.rmi.registry.RegistryContext#decodeObject
```java
    private Object decodeObject(Remote var1, Name var2) throws NamingException {
        try {
            Object var3 = var1 instanceof RemoteReference ? ((RemoteReference)var1).getReference() : var1;
            Reference var8 = null;
            if (var3 instanceof Reference) {
                var8 = (Reference)var3;
            } else if (var3 instanceof Referenceable) {
                var8 = ((Referenceable)((Referenceable)var3)).getReference();
            }

            if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase) {
                throw new ConfigurationException("The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.");
            } else {
                return NamingManager.getObjectInstance(var3, var2, this, this.environment);
            }
        } catch (NamingException var5) {
            throw var5;
        } catch (RemoteException var6) {
            throw (NamingException)wrapRemoteException(var6).fillInStackTrace();
        } catch (Exception var7) {
            NamingException var4 = new NamingException();
            var4.setRootCause(var7);
            throw var4;
        }
    }
```

Oracle在jdk8u191之后设置了com.sun.jndi.ldap.object.trustURLCodebase为 false,限制了LDAP 利用是从远程加载 Class

com.sun.naming.internal.VersionHelper12#loadClass(java.lang.String, java.lang.String)

```java
    public Class<?> loadClass(String className, String codebase)
            throws ClassNotFoundException, MalformedURLException {
        if ("true".equalsIgnoreCase(trustURLCodebase)) {
            ClassLoader parent = getContextClassLoader();
            ClassLoader cl =
                    URLClassLoader.newInstance(getUrlArray(codebase), parent);

            return loadClass(className, cl);
        } else {
            return null;
        }
    }
```

#### 绕过

针对 RMI 利用的检查方式中最关键的就是 ```if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase)``` 如果 FactoryClassLocation 为空，那么就会进入 ```NamingManager.getObjectInstance``` 在此方法会调用 Reference 中的ObjectFactory。因此绕过思路为在目标 classpath 中寻找实现 ObjectFactory 接口的类。在 Tomcat 中有一处可以利用的符合条件的类```org.apache.naming.factory.BeanFactory``` 在此类中会获取 Reference 中的```forceString```
得到其中的值之后会判断是否包含等号，如果包含则用等号分割，将前一半当做方法名，后一半当做 Hashmap 中的 key。如果不包含等号则方法名变成 set开头。值得注意的是此方法中已经指定了参数类型为 String。后面将会利用反射执行前面所提到的方法。因此需要找到使用了 String 作为参数，并且能 RCE的方法。在```javax.el.ELProcessor``` 中的 eval 方法就很合适
```
 public Object eval(String expression) {
        return this.getValue(expression, Object.class);
    }
```

![Demo](/old_img/JNDI-Injection-Demo.gif)

#### 参考
https://www.veracode.com/blog/research/exploiting-jndi-injections-java
