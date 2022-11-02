

# jwt

## 认证机制介绍

### HTTP Basic Auth

HTTP Basic Auth 是一种简单的登录认证方式，Web浏览器或其他客户端程序在请求时提供用户名和密码，通常用户名和密码会通过HTTP头传递。简单点说就是每次请求时都提供用户的username和password

这种方式是先把用户名、冒号、密码拼接起来，并将得出的结果字符串用Base64算法编码。

例如，提供的用户名是 `bill` 、口令是 `123456` ，则拼接后的结果就是 `bill:123456` ，然后再将其用Base64编码，得到 `YmlsbDoxMjM0NTY=` 。最终将Base64编码的字符串发送出去，由接收者解码得到一个由冒号分隔的用户名和口令的字符串。



**优点：**

基本上所有流行的网页浏览器都支持基本认证。

**缺点：**

由于用户名和密码都是Base64编码的，而Base64编码是可逆的，所以用户名和密码可以认为是明文。所以只有在客户端和服务器主机之间的连接是安全可信的前提下才可以使用。







### Cookie-Session Auth

Cookie-session 认证机制是通过浏览器带上来Cookie对象来与服务器端的session对象匹配来实现状态管理。

第一次请求认证在服务端创建一个Session对象，同时在用户的浏览器端创建了一个Cookie对象；当我们关闭浏览器的时候，cookie会被删除。但可以通过修改cookie 的expire time使cookie在一定时间内有效。



**优点：**

相对HTTP Basic Auth更加安全。

**缺点：**

这种基于cookie-session的认证使应用本身很难得到扩展，随着不同客户端用户的增加，独立的服务器已无法承载更多的用户，而这时候基于session认证应用的问题就会暴露出来。







### OAuth

OAuth 是一个关于授权（authorization）的开放网络标准。允许用户提供一个令牌，而不是用户名和密码来访问他们存放在特定服务提供者的数据。现在的版本是2.0版。

严格来说，OAuth2不是一个标准协议，而是一个安全的授权框架。它详细描述了系统中不同角色、用户、服务前端应用（比如API），以及客户端（比如网站或移动App）之间怎么实现相互认证。



![image-20221102132057355](img/jwt学习笔记/image-20221102132057355.png)







**优点：**

- 快速开发，代码量小，维护工作少。
- 如果API要被不同的App使用，并且每个App使用的方式也不一样，使用OAuth2是个不错的选择。

**缺点：**

OAuth2是一个安全框架，描述了在各种不同场景下，多个应用之间的授权问题。有海量的资料需要学习，要完全理解需要花费大量时间。OAuth2不是一个严格的标准协议，因此在实施过程中更容易出错。







### Token Auth

基于token的认证鉴权机制类似于http协议，也是无状态的。这种方式不需要在服务端去保留用户的认证信息或者会话信息。这就意味着基于token认证机制的应用不需要去考虑用户在哪一台服务器登录了，这就为应用的扩展提供了便利。

这个token必须要在每次请求时传递给服务端，它应该保存在请求头中，Token Auth 流程如下图：



![image-20221102132206900](img/jwt学习笔记/image-20221102132206900.png)





**优点：**

- 支持跨域访问
- Token机制在服务端不需要存储session信息：Token 自身包含了所有登录用户的信息，只需要在客户端的cookie或本地介质存储状态信息
- 去耦：不需要绑定到一个特定的身份验证方案。Token可以在任何地方生成，只要在你的API被调用的时候，你可以进行Token生成调用即可
- 更适用于移动应用：Cookie是不被客户端（iOS, Android，Windows 8等）支持的。
- 基于标准化：
  API可以采用标准化的 JSON Web Token (JWT)。这个标准已经存在多个后端库（.NET, Ruby, Java,Python, PHP）和多家公司的支持（如：Firebase,Google, Microsoft）

**缺点：**

- 占带宽
  正常情况下要比 session_id 更大，需要消耗更多流量，挤占更多带宽，假如你的网站每月有 10 万次的浏览器，就意味着要多开销几十兆的流量。听起来并不多，但日积月累也是不小一笔开销。实际上，许多人会在 JWT 中存储的信息会更多
- 无法在服务端注销，因为服务端是无状态的，并没有保存客户端用户登录信息
- 对于有着严格性能要求的 Web 应用并不理想，尤其对于单线程环境 











## JWT介绍

JWT全称为JSON Web Token，是目前最流行的跨域身份验证解决方案。JWT是为了在网络应用环境间传递声明而制定的一种基于JSON的开放标准。

JWT特别适用于分布式站点的单点登录（SSO）场景。JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可被加密。







## JWT的数据结构

WT其实就是一个很长的字符串，字符之间通过"."分隔符分为三个子串，各字串之间没有换行符。每一个子串表示了一个功能块，总共有三个部分：**JWT头(header)**、**有效载荷(payload)**、**签名(signature)**，如下图所示：



![image-20221102132631722](img/jwt学习笔记/image-20221102132631722.png)







###  JWT头

JWT头是一个描述JWT元数据的JSON对象，通常如下所示：

~~~json
{"alg": "HS256","typ": "JWT"}
~~~

alg：表示签名使用的算法，默认为HMAC SHA256（写为HS256）

typ：表示令牌的类型，JWT令牌统一写为JWT

最后，使用Base64 URL算法将上述JSON对象转换为字符串







### 有效载荷

有效载荷，是JWT的主体内容部分，也是一个JSON对象，包含需要传递的数据。 

有效载荷部分规定有如下七个默认字段供选择：

~~~
iss：发行人
exp：到期时间
sub：主题
aud：用户
nbf：在此之前不可用
iat：发布时间
jti：JWT ID用于标识该JWT
~~~

除以上默认字段外，还可以自定义私有字段。

最后，同样使用Base64 URL算法将有效载荷部分JSON对象转换为字符串







### 签名

签名实际上是一个加密的过程，是对上面两部分数据通过指定的算法生成哈希，以确保数据不会被篡改。

首先需要指定一个密码（secret），该密码仅仅保存在服务器中，并且不能向用户公开。然后使用JWT头中指定的签名算法（默认情况下为HMAC SHA256），根据以下公式生成签名哈希：



```sh
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),secret)
```



在计算出签名哈希后，JWT头，有效载荷和签名哈希的三个部分组合成一个字符串，每个部分用"."分隔，就构成整个JWT对象









## JWT签名算法

JWT签名算法中，一般有两个选择：HS256和RS256。

HS256 (带有 SHA-256 的 HMAC )是一种对称加密算法, 双方之间仅共享一个密钥。由于使用相同的密钥生成签名和验证签名, 因此必须注意确保密钥不被泄密。

RS256 (采用SHA-256 的 RSA 签名) 是一种非对称加密算法, 它使用公共/私钥对: JWT的提供方采用私钥生成签名, JWT 的使用方获取公钥以验证签名。







## jjwt介绍

jjwt是一个提供JWT创建和验证的Java库。永远免费和开源(Apache License，版本2.0)，JJWT很容易使用和理解。

jjwt的maven坐标：

~~~xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
~~~









## jwt入门案例



### 第一步：创建maven工程jwt_demo并配置pom.xml文件



```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <!--
      -maven项目核心配置文件-
    Project name(项目名称)：jwt_demo
    Author(作者）: mao
    Author QQ：1296193245
    GitHub：https://github.com/maomao124/
    Date(创建日期)： 2022/11/2
    Time(创建时间)： 13:36
    -->
    <groupId>mao</groupId>
    <artifactId>jwt_demo</artifactId>

    <version>1.0-SNAPSHOT</version>
    <description>使用jjwt来解析和生成token</description>

    <properties>

        <maven.compiler.source>16</maven.compiler.source>
        <maven.compiler.target>16</maven.compiler.target>
    </properties>

    <dependencies>
        <!--jwt 依赖-->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>

        <!-- 测试框架 -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>RELEASE</version>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-all</artifactId>
            <version>5.8.0</version>
        </dependency>

        <!--java 8 版本不需要添加-->
        <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-impl</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-core</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>javax.activation</groupId>
            <artifactId>activation</artifactId>
            <version>1.1.1</version>
        </dependency>

    </dependencies>

</project>
```









### 第二步：编写单元测试





```java
/**
 * 生成token，不使用签名
 */
@Test
void test1()
{
    Map<String, Object> head = new HashMap<>();
    head.put("alg", "none");
    head.put("typ", "JWT");

    Map<String, Object> body = new HashMap<>();
    body.put("userId", "10001");
    body.put("username", "张三");
    body.put("sex", "男");

    String token = Jwts.builder()
            .setHeader(head)
            .setClaims(body)
            .setId("jwt1")
            .compact();
    System.out.println(token);
    //eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMSIsImp0aSI6Imp3dDEiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.
}
```





![image-20221102201655194](img/jwt学习笔记/image-20221102201655194.png)







```java
/**
 * 解析token，不使用签名
 */
@Test
void test2()
{
    Jwt jwt = Jwts.parser().parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0." +
            "eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMSIsImp0aSI6Imp3dDEiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.");
    Header header = jwt.getHeader();
    Object body = jwt.getBody();
    System.out.println(jwt);
    System.out.println(header);
    System.out.println(body);
}
```





![image-20221102201720015](img/jwt学习笔记/image-20221102201720015.png)







```java
/**
 * 生成token，使用hs256签名算法
 */
@Test
void test3()
{
    Map<String, Object> head = new HashMap<>();
    head.put("alg", SignatureAlgorithm.HS256.getValue());
    head.put("typ", "JWT");

    Map<String, Object> body = new HashMap<>();
    body.put("userId", "10002");
    body.put("username", "张三");
    body.put("sex", "男");

    String token = Jwts.builder()
            .setHeader(head)
            .setClaims(body)
            .setId("jwt2")
            .signWith(SignatureAlgorithm.HS256, "123456")
            .compact();
    System.out.println(token);
    //eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
    // .eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9
    // .9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98
}
```





![image-20221102202410308](img/jwt学习笔记/image-20221102202410308.png)







```java
/**
 * 解析token，使用hs256签名算法，不设置SigningKey的情况
 */
@Test
void test4()
{
    String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
            ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
            "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

    Jwt jwt = Jwts.parser()
            .parse(token);
    Header header = jwt.getHeader();
    Object body = jwt.getBody();
    System.out.println(jwt);
    System.out.println(header);
    System.out.println(body);
}
```





![image-20221102203047618](img/jwt学习笔记/image-20221102203047618.png)







```java
/**
 * 解析token，使用hs256签名算法，SigningKey错误的情况
 */
@Test
void test5()
{
    String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
            ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
            "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

    Jwt jwt = Jwts.parser()
            .setSigningKey("1236")
            .parse(token);
    Header header = jwt.getHeader();
    Object body = jwt.getBody();
    System.out.println(jwt);
    System.out.println(header);
    System.out.println(body);
}
```





![image-20221102203218770](img/jwt学习笔记/image-20221102203218770.png)







```java
/**
 * 解析token，使用hs256签名算法，SigningKey正确的情况
 */
@Test
void test6()
{
    String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
            ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
            "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

    Jwt jwt = Jwts.parser()
            .setSigningKey("123456")
            .parse(token);
    Header header = jwt.getHeader();
    Object body = jwt.getBody();
    System.out.println(jwt);
    System.out.println(header);
    System.out.println(body);
}
```





![image-20221102203300576](img/jwt学习笔记/image-20221102203300576.png)







```java
/**
 * 生成jwt令牌，基于RS256签名算法，错误
 */
@Test
void test7()
{
    Map<String, Object> head = new HashMap<>();
    head.put("alg", SignatureAlgorithm.RS256.getValue());
    head.put("typ", "JWT");

    Map<String, Object> body = new HashMap<>();
    body.put("userId", "10003");
    body.put("username", "张三");
    body.put("sex", "男");

    String token = Jwts.builder()
            .setHeader(head)
            .setClaims(body)
            .setId("jwt3")
            .signWith(SignatureAlgorithm.RS256, "123456")
            .compact();
    System.out.println(token);
}
```



![image-20221102203810652](img/jwt学习笔记/image-20221102203810652.png)







需要先生成秘钥/公钥 对



```java
/**
 * 生成自己的 秘钥/公钥 对
 *
 * @throws Exception 异常
 */
@Test
public void test8() throws Exception
{
    //自定义 随机密码,  请修改这里
    String password = "123456";

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    SecureRandom secureRandom = new SecureRandom(password.getBytes());
    keyPairGenerator.initialize(1024, secureRandom);
    KeyPair keyPair = keyPairGenerator.genKeyPair();

    byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
    byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

    FileUtil.writeBytes(publicKeyBytes, "./pub.key");
    FileUtil.writeBytes(privateKeyBytes, "./pri.key");
}
```







```java
    //获取私钥
    public PrivateKey getPriKey() throws Exception
    {
//        InputStream inputStream =
//                this.getClass().getClassLoader().getResourceAsStream("pri.key");
        FileInputStream inputStream = new FileInputStream("./pri.key");
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        byte[] keyBytes = new byte[inputStream.available()];
        dataInputStream.readFully(keyBytes);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    //获取公钥
    public PublicKey getPubKey() throws Exception
    {
//        InputStream inputStream =
//                this.getClass().getClassLoader().getResourceAsStream("pub.key");
        FileInputStream inputStream = new FileInputStream("./pub.key");
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        byte[] keyBytes = new byte[inputStream.available()];
        dataInputStream.readFully(keyBytes);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * 生成jwt令牌，基于RS256签名算法
     */
    @Test
    void test9() throws Exception
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10003");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt3")
                .signWith(SignatureAlgorithm.RS256, getPriKey())
                .compact();
        System.out.println(token);
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMyIsImp0aSI6Imp3dDMiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.Ke2o0WFNNQp71Sdd056bP2Z2CywxfaV4M9OUtsPNBmrLWSLNOkqUao3DiTdX2kLMMWjVQ4THnCQHRiJhXa2uPX6qLfNPHhCC1unYFBlU17WAPSfpp3BeEF4UK3G5GOiamLFghiowlwG84_3AuNFOj8JZXY4Beq_FpT9PSo1608M
    }
```







![image-20221102204938691](img/jwt学习笔记/image-20221102204938691.png)







```java
/**
 * 解析jwt令牌，基于RS256签名算法
 */
@Test
void test10() throws Exception
{
    String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" +
            ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMyIsImp0aSI6Imp3dDMiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9" +
            ".Ke2o0WFNNQp71Sdd056bP2Z2CywxfaV4M9OUtsPNBmrLWSLNOkqUao3DiTdX2kLMMWjVQ4" +
            "THnCQHRiJhXa2uPX6qLfNPHhCC1unYFBlU17WAPSfpp3BeEF4UK3G5GOiamLFghiowlwG84_3AuNFOj8JZXY4Beq_FpT9PSo1608M";

    Jwt jwt = Jwts.parser()
            .setSigningKey(getPubKey())
            .parse(token);
    Header header = jwt.getHeader();
    Object body = jwt.getBody();
    System.out.println(jwt);
    System.out.println(header);
    System.out.println(body);
}
```





![image-20221102205357079](img/jwt学习笔记/image-20221102205357079.png)







```java
/**
 * 生成jwt令牌，基于RS256签名算法，带过期时间，解析过期的情况
 */
@Test
void test11() throws Exception
{
    Map<String, Object> head = new HashMap<>();
    head.put("alg", SignatureAlgorithm.RS256.getValue());
    head.put("typ", "JWT");

    Map<String, Object> body = new HashMap<>();
    body.put("userId", "10004");
    body.put("username", "张三");
    body.put("sex", "男");

    String token = Jwts.builder()
            .setHeader(head)
            .setClaims(body)
            .setExpiration(new Date(new Date().getTime() + 2 * 1000))//2秒
            .setId("jwt4")
            .signWith(SignatureAlgorithm.RS256, getPriKey())
            .compact();
    System.out.println(token);


    Thread.sleep(2000);

    Jwt jwt = Jwts.parser()
            .setSigningKey(getPubKey())
            .parse(token);
    Header header = jwt.getHeader();
    Object body2 = jwt.getBody();
    System.out.println(jwt);
    System.out.println(header);
    System.out.println(body2);
}
```





![image-20221102210100559](img/jwt学习笔记/image-20221102210100559.png)









```java
/**
 * 生成jwt令牌，基于RS256签名算法，带过期时间，解析没有过期的情况
 */
@Test
void test12() throws Exception
{
    Map<String, Object> head = new HashMap<>();
    head.put("alg", SignatureAlgorithm.RS256.getValue());
    head.put("typ", "JWT");

    Map<String, Object> body = new HashMap<>();
    body.put("userId", "10004");
    body.put("username", "张三");
    body.put("sex", "男");

    String token = Jwts.builder()
            .setHeader(head)
            .setClaims(body)
            .setExpiration(new Date(new Date().getTime() + 2 * 1000))//2秒
            .setId("jwt4")
            .signWith(SignatureAlgorithm.RS256, getPriKey())
            .compact();
    System.out.println(token);


    //Thread.sleep(2000);

    System.out.println("\n-------\n");

    Jwt jwt = Jwts.parser()
            .setSigningKey(getPubKey())
            .parse(token);
    Header header = jwt.getHeader();
    Object body2 = jwt.getBody();
    System.out.println(jwt);
    System.out.println(header);
    System.out.println(body2);
}
```





![image-20221102210252811](img/jwt学习笔记/image-20221102210252811.png)









全部源码：

```java
package mao;

import cn.hutool.core.io.FileUtil;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Project name(项目名称)：jwt_demo
 * Package(包名): mao
 * Class(类名): JwtTest
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 13:40
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class JwtTest
{

    /**
     * 生成token，不使用签名
     */
    @Test
    void test1()
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", "none");
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10001");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt1")
                .compact();
        System.out.println(token);
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMSIsImp0aSI6Imp3dDEiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.
    }

    /**
     * 解析token，不使用签名
     */
    @Test
    void test2()
    {
        Jwt jwt = Jwts.parser().parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0." +
                "eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMSIsImp0aSI6Imp3dDEiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.");
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }


    /**
     * 生成token，使用hs256签名算法
     */
    @Test
    void test3()
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.HS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10002");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt2")
                .signWith(SignatureAlgorithm.HS256, "123456")
                .compact();
        System.out.println(token);
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
        // .eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9
        // .9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98
    }

    /**
     * 解析token，使用hs256签名算法，不设置SigningKey的情况
     */
    @Test
    void test4()
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
                "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

        Jwt jwt = Jwts.parser()
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }


    /**
     * 解析token，使用hs256签名算法，SigningKey错误的情况
     */
    @Test
    void test5()
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
                "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

        Jwt jwt = Jwts.parser()
                .setSigningKey("1236")
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }

    /**
     * 解析token，使用hs256签名算法，SigningKey正确的情况
     */
    @Test
    void test6()
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
                "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

        Jwt jwt = Jwts.parser()
                .setSigningKey("123456")
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }


    /**
     * 生成jwt令牌，基于RS256签名算法，错误
     */
    @Test
    void test7()
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10003");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt3")
                .signWith(SignatureAlgorithm.RS256, "123456")
                .compact();
        System.out.println(token);
    }


    /**
     * 生成自己的 秘钥/公钥 对
     *
     * @throws Exception 异常
     */
    @Test
    public void test8() throws Exception
    {
        //自定义 随机密码,  请修改这里
        String password = "123456";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom(password.getBytes());
        keyPairGenerator.initialize(1024, secureRandom);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        FileUtil.writeBytes(publicKeyBytes, "./pub.key");
        FileUtil.writeBytes(privateKeyBytes, "./pri.key");
    }

    //获取私钥
    public PrivateKey getPriKey() throws Exception
    {
//        InputStream inputStream =
//                this.getClass().getClassLoader().getResourceAsStream("pri.key");
        FileInputStream inputStream = new FileInputStream("./pri.key");
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        byte[] keyBytes = new byte[inputStream.available()];
        dataInputStream.readFully(keyBytes);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    //获取公钥
    public PublicKey getPubKey() throws Exception
    {
//        InputStream inputStream =
//                this.getClass().getClassLoader().getResourceAsStream("pub.key");
        FileInputStream inputStream = new FileInputStream("./pub.key");
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        byte[] keyBytes = new byte[inputStream.available()];
        dataInputStream.readFully(keyBytes);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * 生成jwt令牌，基于RS256签名算法
     */
    @Test
    void test9() throws Exception
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10003");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt3")
                .signWith(SignatureAlgorithm.RS256, getPriKey())
                .compact();
        System.out.println(token);
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwM
        // yIsImp0aSI6Imp3dDMiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.Ke2o0WFNNQp71Sdd056bP2Z2
        // CywxfaV4M9OUtsPNBmrLWSLNOkqUao3DiTdX2kLMMWjVQ4THnCQHRiJhXa2uPX6qLfNPHh
        // CC1unYFBlU17WAPSfpp3BeEF4UK3G5GOiamLFghiowlwG84_3AuNFOj8JZXY4Beq_FpT9PSo1608M
    }

    /**
     * 解析jwt令牌，基于RS256签名算法
     */
    @Test
    void test10() throws Exception
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMyIsImp0aSI6Imp3dDMiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9" +
                ".Ke2o0WFNNQp71Sdd056bP2Z2CywxfaV4M9OUtsPNBmrLWSLNOkqUao3DiTdX2kLMMWjVQ4" +
                "THnCQHRiJhXa2uPX6qLfNPHhCC1unYFBlU17WAPSfpp3BeEF4UK3G5GOiamLFghiowlwG84_3AuNFOj8JZXY4Beq_FpT9PSo1608M";

        Jwt jwt = Jwts.parser()
                .setSigningKey(getPubKey())
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }

    /**
     * 生成jwt令牌，基于RS256签名算法，带过期时间，解析过期的情况
     */
    @Test
    void test11() throws Exception
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10004");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setExpiration(new Date(new Date().getTime() + 2 * 1000))//2秒
                .setId("jwt4")
                .signWith(SignatureAlgorithm.RS256, getPriKey())
                .compact();
        System.out.println(token);


        Thread.sleep(2000);

        Jwt jwt = Jwts.parser()
                .setSigningKey(getPubKey())
                .parse(token);
        Header header = jwt.getHeader();
        Object body2 = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body2);
    }


    /**
     * 生成jwt令牌，基于RS256签名算法，带过期时间，解析没有过期的情况
     */
    @Test
    void test12() throws Exception
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10004");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setExpiration(new Date(new Date().getTime() + 2 * 1000))//2秒
                .setId("jwt4")
                .signWith(SignatureAlgorithm.RS256, getPriKey())
                .compact();
        System.out.println(token);


        //Thread.sleep(2000);

        System.out.println("\n-------\n");

        Jwt jwt = Jwts.parser()
                .setSigningKey(getPubKey())
                .parse(token);
        Header header = jwt.getHeader();
        Object body2 = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body2);
    }
}
```

















## 自定义spring boot starter

### 开发starter



第一步：初始化项目



创建父工程jwt_spring_boot_starter



![image-20221102215656128](img/jwt学习笔记/image-20221102215656128.png)





创建子工程tools-jwt



![image-20221102215901750](img/jwt学习笔记/image-20221102215901750.png)





创建子工程use-starter



![image-20221102215939619](img/jwt学习笔记/image-20221102215939619.png)







第二步：修改pom文件



父工程jwt_spring_boot_starter的pom文件：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.1</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <groupId>mao</groupId>
    <artifactId>jwt_spring_boot_starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>jwt_spring_boot_starter</name>
    <description>jwt_spring_boot_starter</description>
    <packaging>pom</packaging>

    <properties>
        <java.version>11</java.version>
    </properties>

    <modules>
        <module>tools-jwt</module>
        <module>use-starter</module>
    </modules>

    <dependencies>

    </dependencies>

    <dependencyManagement>
        <dependencies>

        </dependencies>
    </dependencyManagement>

</project>
```





子工程tools-jwt的pom文件：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
       <artifactId>jwt_spring_boot_starter</artifactId>
        <groupId>mao</groupId>
        <version>0.0.1-SNAPSHOT</version>
    </parent>

    <artifactId>tools-jwt</artifactId>
    <name>tools-jwt</name>
    <description>tools-jwt</description>
    <properties>

    </properties>

    <dependencies>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <!--jwt 依赖-->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>

        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-all</artifactId>
            <version>5.8.0</version>
        </dependency>

        <!--java 8 版本不需要添加-->
        <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-impl</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-core</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>javax.activation</groupId>
            <artifactId>activation</artifactId>
            <version>1.1.1</version>
        </dependency>

    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <skip>true</skip>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-resources-plugin</artifactId>
                <configuration>
                    <encoding>UTF-8</encoding>
                    <!-- 过滤后缀为pem、pfx的证书文件 -->
                    <nonFilteredFileExtensions>
                        <nonFilteredFileExtension>pem</nonFilteredFileExtension>
                        <nonFilteredFileExtension>pfx</nonFilteredFileExtension>
                        <nonFilteredFileExtension>p12</nonFilteredFileExtension>
                        <nonFilteredFileExtension>key</nonFilteredFileExtension>
                    </nonFilteredFileExtensions>
                </configuration>
            </plugin>
        </plugins>
    </build>



</project>
```





子工程use-starter的pom文件：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <artifactId>jwt_spring_boot_starter</artifactId>
        <groupId>mao</groupId>
        <version>0.0.1-SNAPSHOT</version>
    </parent>

    <artifactId>use-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>use-starter</name>
    <description>use-starter</description>
    <properties>

    </properties>

    <dependencies>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```







第三步：编写实体类JwtUserInfo



```java
package com.example.tools_jwt.entity;

import java.io.Serializable;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.entity
 * Class(类名): JwtUserInfo
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:12
 * Version(版本): 1.0
 * Description(描述)： 无
 */


public class JwtUserInfo implements Serializable
{
    /**
     * 账号id
     */
    private Long userId;
    /**
     * 账号
     */
    private String account;
    /**
     * 姓名
     */
    private String name;

    /**
     * 当前登录人单位id
     */
    private Long orgId;

    /**
     * 当前登录人岗位ID
     */
    private Long stationId;

    /**
     * Instantiates a new Jwt user info.
     */
    public JwtUserInfo()
    {

    }

    /**
     * Instantiates a new Jwt user info.
     *
     * @param userId    the user id
     * @param account   the account
     * @param name      the name
     * @param orgId     the org id
     * @param stationId the station id
     */
    public JwtUserInfo(Long userId, String account, String name, Long orgId, Long stationId)
    {
        this.userId = userId;
        this.account = account;
        this.name = name;
        this.orgId = orgId;
        this.stationId = stationId;
    }

    /**
     * Gets user id.
     *
     * @return the user id
     */
    public Long getUserId()
    {
        return userId;
    }

    /**
     * Sets user id.
     *
     * @param userId the user id
     */
    public void setUserId(Long userId)
    {
        this.userId = userId;
    }

    /**
     * Gets account.
     *
     * @return the account
     */
    public String getAccount()
    {
        return account;
    }

    /**
     * Sets account.
     *
     * @param account the account
     */
    public void setAccount(String account)
    {
        this.account = account;
    }

    /**
     * Gets name.
     *
     * @return the name
     */
    public String getName()
    {
        return name;
    }

    /**
     * Sets name.
     *
     * @param name the name
     */
    public void setName(String name)
    {
        this.name = name;
    }

    /**
     * Gets org id.
     *
     * @return the org id
     */
    public Long getOrgId()
    {
        return orgId;
    }

    /**
     * Sets org id.
     *
     * @param orgId the org id
     */
    public void setOrgId(Long orgId)
    {
        this.orgId = orgId;
    }

    /**
     * Gets station id.
     *
     * @return the station id
     */
    public Long getStationId()
    {
        return stationId;
    }

    /**
     * Sets station id.
     *
     * @param stationId the station id
     */
    public void setStationId(Long stationId)
    {
        this.stationId = stationId;
    }

    @Override
    public String toString()
    {
        final StringBuffer sb = new StringBuffer("JwtUserInfo{");
        sb.append("userId=").append(userId);
        sb.append(", account='").append(account).append('\'');
        sb.append(", name='").append(name).append('\'');
        sb.append(", orgId=").append(orgId);
        sb.append(", stationId=").append(stationId);
        sb.append('}');
        return sb.toString();
    }
}
```





第四步：编写实体类Token



```java
package com.example.tools_jwt.entity;

import io.swagger.annotations.ApiModelProperty;

import java.io.Serializable;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.entity
 * Class(类名): Token
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:15
 * Version(版本): 1.0
 * Description(描述)： 无
 */
public class Token implements Serializable
{
    private static final long serialVersionUID = -8482946147572784305L;

    /**
     * token
     */
    @ApiModelProperty(value = "token")
    private String token;
    /**
     * 有效时间：单位：秒
     */
    @ApiModelProperty(value = "token的有效期")
    private Integer expire;

    /**
     * Instantiates a new Token.
     */
    public Token()
    {

    }

    /**
     * Instantiates a new Token.
     *
     * @param token  the token
     * @param expire the expire
     */
    public Token(String token, Integer expire)
    {
        this.token = token;
        this.expire = expire;
    }

    /**
     * Gets token.
     *
     * @return the token
     */
    public String getToken()
    {
        return token;
    }

    /**
     * Sets token.
     *
     * @param token the token
     */
    public void setToken(String token)
    {
        this.token = token;
    }

    /**
     * Gets expire.
     *
     * @return the expire
     */
    public Integer getExpire()
    {
        return expire;
    }

    /**
     * Sets expire.
     *
     * @param expire the expire
     */
    public void setExpire(Integer expire)
    {
        this.expire = expire;
    }
}
```





第五步：编写工具类RsaKeyHelper



```java
package com.example.tools_jwt.utils;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.utils
 * Class(类名): RsaKeyHelper
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:19
 * Version(版本): 1.0
 * Description(描述)： Rsa key 帮助类
 */

public class RsaKeyHelper
{

    /**
     * 获取公钥,用于解析token
     *
     * @param filename 文件名
     * @return {@link PublicKey}
     * @throws IOException              ioexception
     * @throws NoSuchAlgorithmException 没有这样算法异常
     * @throws InvalidKeySpecException  无效关键规范异常
     */
    public PublicKey getPublicKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(filename);
        if (inputStream == null)
        {
            throw new IOException("获取公钥时获取失败，可能是公钥文件不存在。当前路径：" + filename);
        }
        try (DataInputStream dataInputStream = new DataInputStream(inputStream))
        {
            byte[] keyBytes = new byte[inputStream.available()];
            dataInputStream.readFully(keyBytes);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        }
    }


    /**
     * 获取私钥 用于生成token
     *
     * @param filename 文件名
     * @return {@link PrivateKey}
     * @throws IOException              ioexception
     * @throws NoSuchAlgorithmException 没有这样算法异常
     * @throws InvalidKeySpecException  无效关键规范异常
     */
    public PrivateKey getPrivateKey(String filename)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(filename);
        if (inputStream == null)
        {
            throw new IOException("获取私钥时获取失败，可能是私钥文件不存在。当前路径：" + filename);
        }
        try (DataInputStream dataInputStream = new DataInputStream(inputStream))
        {
            byte[] keyBytes = new byte[inputStream.available()];
            dataInputStream.readFully(keyBytes);

            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        }
    }
}
```





第六步：编写工具类NumberHelper



```java
package com.example.tools_jwt.utils;

import java.util.function.Function;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.utils
 * Class(类名): NumberHelper
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:27
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class NumberHelper
{
    private static <T, R> R valueOfDef(T t, Function<T, R> function, R def)
    {
        try
        {
            return function.apply(t);
        }
        catch (Exception e)
        {
            return def;
        }
    }

    public static Long longValueOfNil(String value)
    {
        return valueOfDef(value, (val) -> Long.valueOf(val), null);
    }

    public static Long longValueOf0(String value)
    {
        return valueOfDef(value, (val) -> Long.valueOf(val), 0L);
    }

    public static Long longValueOfNil(Object value)
    {
        return valueOfDef(value, (val) -> Long.valueOf(val.toString()), null);
    }

    public static Long longValueOf0(Object value)
    {
        return valueOfDef(value, (val) -> Long.valueOf(val.toString()), 0L);
    }

    public static Boolean boolValueOf0(Object value)
    {
        return valueOfDef(value, (val) -> Boolean.valueOf(val.toString()), false);
    }

    public static Integer intValueOfNil(String value)
    {
        return valueOfDef(value, (val) -> Integer.valueOf(val), null);
    }

    public static Integer intValueOf0(String value)
    {
        return intValueOf(value, 0);
    }

    public static Integer intValueOf(String value, Integer def)
    {
        return valueOfDef(value, (val) -> Integer.valueOf(val), def);
    }

    public static Integer intValueOfNil(Object value)
    {
        return valueOfDef(value, (val) -> Integer.valueOf(val.toString()), null);
    }

    public static Integer intValueOf0(Object value)
    {
        return valueOfDef(value, (val) -> Integer.valueOf(val.toString()), 0);
    }

    public static Integer getOrDef(Integer val, Integer def)
    {
        return val == null ? def : val;
    }

    public static Long getOrDef(Long val, Long def)
    {
        return val == null ? def : val;
    }

    public static Boolean getOrDef(Boolean val, Boolean def)
    {
        return val == null ? def : val;
    }
}
```





第七步：编写工具类StrHelper



```java
package com.example.tools_jwt.utils;

import cn.hutool.core.util.StrUtil;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.utils
 * Class(类名): StrHelper
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:28
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class StrHelper
{
    public static String getObjectValue(Object obj)
    {
        return obj == null ? "" : obj.toString();
    }

    public static String encode(String value)
    {
        try
        {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        }
        catch (Exception e)
        {
            return "";
        }
    }

    public static String decode(String value)
    {
        try
        {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        }
        catch (Exception e)
        {
            return "";
        }
    }

    public static String getOrDef(String val, String def)
    {
        return StrUtil.isEmpty(val) ? def : val;
    }
}
```







第八步：编写接口BaseException



```java
package com.example.tools_jwt.exception;

/**
 * 异常接口类
 */
public interface BaseException
{

    /**
     * 统一参数验证异常码
     */
    int BASE_VALID_PARAM = -9;

    /**
     * 返回异常信息
     *
     * @return {@link String}
     */
    String getMessage();

    /**
     * 返回异常编码
     *
     * @return int
     */
    int getCode();

}
```





第九步：编写接口BaseExceptionCode



```java
package com.example.tools_jwt.exception;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.exception
 * Interface(接口名): BaseExceptionCode
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:32
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public interface BaseExceptionCode
{
    /**
     * 异常编码
     *
     * @return int
     */
    int getCode();

    /**
     * 异常消息
     *
     * @return String
     */
    String getMsg();
}
```





第十步：编写类BaseUncheckedException



```java
package com.example.tools_jwt.exception;

/**
 * 非运行期异常基类，所有自定义非运行时异常继承该类
 */
public class BaseUncheckedException extends RuntimeException implements BaseException
{

    private static final long serialVersionUID = -778887391066124051L;

    /**
     * 异常信息
     */
    protected String message;

    /**
     * 具体异常码
     */
    protected int code;

    public BaseUncheckedException(int code, String message)
    {
        super(message);
        this.code = code;
        this.message = message;
    }

    public BaseUncheckedException(int code, String format, Object... args)
    {
        super(String.format(format, args));
        this.code = code;
        this.message = String.format(format, args);
    }


    @Override
    public String getMessage()
    {
        return message;
    }

    @Override
    public int getCode()
    {
        return code;
    }
}
```





第十一步：编写类ExceptionCode



```java
package com.example.tools_jwt.exception;

/**
 * 全局错误码 10000-15000
 * <p>
 * 预警异常编码    范围： 30000~34999
 * 标准服务异常编码 范围：35000~39999
 * 邮件服务异常编码 范围：40000~44999
 * 短信服务异常编码 范围：45000~49999
 * 权限服务异常编码 范围：50000-59999
 * 文件服务异常编码 范围：60000~64999
 * 日志服务异常编码 范围：65000~69999
 * 消息服务异常编码 范围：70000~74999
 * 开发者平台异常编码 范围：75000~79999
 * 搜索服务异常编码 范围：80000-84999
 * 共享交换异常编码 范围：85000-89999
 * 移动终端平台 异常码 范围：90000-94999
 * <p>
 * 安全保障平台    范围：        95000-99999
 * 软硬件平台 异常编码 范围：    100000-104999
 * 运维服务平台 异常编码 范围：  105000-109999
 * 统一监管平台异常 编码 范围：  110000-114999
 * 认证方面的异常编码  范围：115000-115999
 */

public enum ExceptionCode implements BaseExceptionCode
{

    //系统相关 start
    SUCCESS(0, "成功"),
    SYSTEM_BUSY(-1, "系统繁忙~请稍后再试~"),
    SYSTEM_TIMEOUT(-2, "系统维护中~请稍后再试~"),
    PARAM_EX(-3, "参数类型解析异常"),
    SQL_EX(-4, "运行SQL出现异常"),
    NULL_POINT_EX(-5, "空指针异常"),
    ILLEGALA_ARGUMENT_EX(-6, "无效参数异常"),
    MEDIA_TYPE_EX(-7, "请求类型异常"),
    LOAD_RESOURCES_ERROR(-8, "加载资源出错"),
    BASE_VALID_PARAM(-9, "统一验证参数异常"),
    OPERATION_EX(-10, "操作异常"),


    OK(200, "OK"),
    BAD_REQUEST(400, "错误的请求"),
    /**
     * {@code 401 Unauthorized}.
     *
     * @see <a href="http://tools.ietf.org/html/rfc7235#section-3.1">HTTP/1.1: Authentication, section 3.1</a>
     */
    UNAUTHORIZED(401, "未经授权"),
    /**
     * {@code 404 Not Found}.
     *
     * @see <a href="http://tools.ietf.org/html/rfc7231#section-6.5.4">HTTP/1.1: Semantics and Content, section 6.5.4</a>
     */
    NOT_FOUND(404, "没有找到资源"),
    METHOD_NOT_ALLOWED(405, "不支持当前请求类型"),

    TOO_MANY_REQUESTS(429, "请求超过次数限制"),
    INTERNAL_SERVER_ERROR(500, "内部服务错误"),
    BAD_GATEWAY(502, "网关错误"),
    GATEWAY_TIMEOUT(504, "网关超时"),
    //系统相关 end

    REQUIRED_FILE_PARAM_EX(1001, "请求中必须至少包含一个有效文件"),
    //jwt token 相关 start

    JWT_TOKEN_EXPIRED(40001, "会话超时，请重新登录"),
    JWT_SIGNATURE(40002, "不合法的token，请认真比对 token 的签名"),
    JWT_ILLEGAL_ARGUMENT(40003, "缺少token参数"),
    JWT_GEN_TOKEN_FAIL(40004, "生成token失败"),
    JWT_PARSER_TOKEN_FAIL(40005, "解析token失败"),
    JWT_USER_INVALID(40006, "用户名或密码错误"),
    JWT_USER_ENABLED(40007, "用户已经被禁用！"),
    //jwt token 相关 end

    ;

    private int code;
    private String msg;

    ExceptionCode(int code, String msg)
    {
        this.code = code;
        this.msg = msg;
    }

    @Override
    public int getCode()
    {
        return code;
    }

    @Override
    public String getMsg()
    {
        return msg;
    }


    public ExceptionCode build(String msg, Object... param)
    {
        this.msg = String.format(msg, param);
        return this;
    }

    public ExceptionCode param(Object... param)
    {
        msg = String.format(msg, param);
        return this;
    }
}
```





第十二步：编写类BizException



```java
package com.example.tools_jwt.exception;

/**
 * 业务异常
 * 用于在处理业务逻辑时，进行抛出的异常。
 */
public class BizException extends BaseUncheckedException
{

    private static final long serialVersionUID = -3843907364558373817L;

    public BizException(String message)
    {
        super(-1, message);
    }

    public BizException(int code, String message)
    {
        super(code, message);
    }

    public BizException(int code, String message, Object... args)
    {
        super(code, message, args);
    }

    /**
     * 实例化异常
     *
     * @param code    自定义异常编码
     * @param message 自定义异常消息
     * @param args    已定义异常参数
     * @return
     */
    public static BizException wrap(int code, String message, Object... args)
    {
        return new BizException(code, message, args);
    }

    public static BizException wrap(String message, Object... args)
    {
        return new BizException(-1, message, args);
    }

    public static BizException validFail(String message, Object... args)
    {
        return new BizException(-9, message, args);
    }

    public static BizException wrap(BaseExceptionCode ex)
    {
        return new BizException(ex.getCode(), ex.getMsg());
    }

    @Override
    public String toString()
    {
        return "BizException [message=" + message + ", code=" + code + "]";
    }

}
```







第十三步：编写常量工具类BaseContextConstants



```java
package com.itheima.pinda.context;

/**
 * 常量工具类
 *
 */
public class BaseContextConstants {
    /**
     *
     */
    public static final String TOKEN_NAME = "token";
    /**
     *
     */
    public static final String JWT_KEY_USER_ID = "userid";
    /**
     *
     */
    public static final String JWT_KEY_NAME = "name";
    /**
     *
     */
    public static final String JWT_KEY_ACCOUNT = "account";

    /**
     * 组织id
     */
    public static final String JWT_KEY_ORG_ID = "orgid";
    /**
     * 岗位id
     */
    public static final String JWT_KEY_STATION_ID = "stationid";

    /**
     * 动态数据库名前缀。  每个项目配置死的
     */
    public static final String DATABASE_NAME = "database_name";
}
```







第十四步：编写日期工具类DateUtils



```java
package com.example.tools_jwt.utils;

import com.example.tools_jwt.exception.BizException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.utils
 * Class(类名): DateUtils
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:30
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class DateUtils
{
    /**
     * 日志
     */
    private static final Logger log = LoggerFactory.getLogger(DateUtils.class);

    /**
     * 默认年格式
     */
    public final static String DEFAULT_YEAR_FORMAT = "yyyy";
    /**
     * 默认月格式
     */
    public final static String DEFAULT_MONTH_FORMAT = "yyyy-MM";
    /**
     * 默认月格式削减
     */
    public final static String DEFAULT_MONTH_FORMAT_SLASH = "yyyy/MM";
    /**
     * 默认月格式在
     */
    public final static String DEFAULT_MONTH_FORMAT_EN = "yyyy年MM月";
    /**
     * 默认星期格式
     */
    public final static String DEFAULT_WEEK_FORMAT = "yyyy-ww";
    /**
     * 默认星期格式在
     */
    public final static String DEFAULT_WEEK_FORMAT_EN = "yyyy年ww周";
    /**
     * 默认日期格式
     */
    public final static String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";
    /**
     * 默认日期格式在
     */
    public final static String DEFAULT_DATE_FORMAT_EN = "yyyy年MM月dd日";
    /**
     * 默认日期时间格式
     */
    public final static String DEFAULT_DATE_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss";
    /**
     * 默认时间格式
     */
    public final static String DEFAULT_TIME_FORMAT = "HH:mm:ss";
    /**
     * 一天
     */
    public final static String DAY = "DAY";
    /**
     * 月
     */
    public final static String MONTH = "MONTH";
    /**
     * 周
     */
    public final static String WEEK = "WEEK";

    /**
     * 最大值月一天
     */
    public final static long MAX_MONTH_DAY = 30;
    /**
     * 最大值3.月一天
     */
    public final static long MAX_3_MONTH_DAY = 90;
    /**
     * 最大值一年一天
     */
    public final static long MAX_YEAR_DAY = 365;


    private DateUtils()
    {
    }
//--格式化日期start-----------------------------------------

    /**
     * 格式化日期,返回格式为 yyyy-MM
     *
     * @param date 日期
     * @return
     */
    public static String format(LocalDateTime date, String pattern)
    {
        if (date == null)
        {
            date = LocalDateTime.now();
        }
        if (pattern == null)
        {
            pattern = DEFAULT_MONTH_FORMAT;
        }
        return date.format(DateTimeFormatter.ofPattern(pattern));
    }

    /**
     * 根据传入的格式格式化日期.默认格式为MM月dd日
     *
     * @param d 日期
     * @param f 格式
     * @return
     */
    public static String format(Date d, String f)
    {
        Date date = d;
        String format = f;
        if (date == null)
        {
            date = new Date();
        }
        if (format == null)
        {
            format = DEFAULT_DATE_TIME_FORMAT;
        }
        SimpleDateFormat df = new SimpleDateFormat(format);
        return df.format(date);
    }

    /**
     * 格式化日期,返回格式为 yyyy-MM-dd
     *
     * @param date 日期
     * @return
     */
    public static String formatAsDate(LocalDateTime date)
    {
        return format(date, DEFAULT_DATE_FORMAT);
    }

    public static String formatAsDateEn(LocalDateTime date)
    {
        return format(date, DEFAULT_DATE_FORMAT_EN);
    }


    public static String formatAsYearMonth(LocalDateTime date)
    {
        return format(date, DEFAULT_MONTH_FORMAT);
    }

    public static String formatAsYearMonthEn(LocalDateTime date)
    {
        return format(date, DEFAULT_MONTH_FORMAT_EN);
    }

    /**
     * 格式化日期,返回格式为 yyyy-ww
     *
     * @param date 日期
     * @return
     */
    public static String formatAsYearWeek(LocalDateTime date)
    {
        return format(date, DEFAULT_WEEK_FORMAT);
    }

    public static String formatAsYearWeekEn(LocalDateTime date)
    {
        return format(date, DEFAULT_WEEK_FORMAT_EN);
    }

    /**
     * 格式化日期,返回格式为 yyyy-MM
     *
     * @param date 日期
     * @return
     */
    public static String formatAsYearMonth(Date date)
    {
        SimpleDateFormat df = new SimpleDateFormat(DEFAULT_MONTH_FORMAT);
        return df.format(date);
    }

    /**
     * 格式化日期,返回格式为 yyyy-ww
     *
     * @param date 日期
     * @return
     */
    public static String formatAsYearWeek(Date date)
    {
        SimpleDateFormat df = new SimpleDateFormat(DEFAULT_WEEK_FORMAT);
        return df.format(date);
    }

    /**
     * 格式化日期,返回格式为 HH:mm:ss 例:12:24:24
     *
     * @param date 日期
     * @return
     */
    public static String formatAsTime(Date date)
    {
        SimpleDateFormat df = new SimpleDateFormat(DEFAULT_TIME_FORMAT);
        return df.format(date);
    }

    /**
     * 格式化日期,返回格式为 yyyy-MM-dd
     *
     * @param date 日期
     * @return
     */
    public static String formatAsDate(Date date)
    {
        SimpleDateFormat df = new SimpleDateFormat(DEFAULT_DATE_FORMAT);
        return df.format(date);
    }

    /**
     * 格式化日期,返回格式为 yyyy-MM-dd HH:mm:ss
     *
     * @param date 日期
     * @return
     */
    public static String formatAsDateTime(Date date)
    {
        SimpleDateFormat df = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT);
        return df.format(date);
    }

    /**
     * 格式化日期,返回格式为 dd ,即对应的天数.
     *
     * @param date 日期
     * @return
     */
    public static String formatAsDay(Date date)
    {
        SimpleDateFormat df = new SimpleDateFormat("dd");
        return df.format(date);
    }

    //--格式化日期end-----------------------------------------

    //--解析日期start-----------------------------------------

    /**
     * 将字符转换成日期
     *
     * @param dateStr
     * @param format
     * @return
     */
    public static Date parse(String dateStr, String format)
    {
        Date date = null;
        SimpleDateFormat sdateFormat = new SimpleDateFormat(format);
        sdateFormat.setLenient(false);
        try
        {
            date = sdateFormat.parse(dateStr);

        }
        catch (Exception e)
        {
            log.info("DateUtils error {} ", e);
        }
        return date;
    }

    /**
     * 根据传入的String返回对应的date
     *
     * @param dateString
     * @return
     */
    public static Date parseAsDate(String dateString)
    {
        SimpleDateFormat df = new SimpleDateFormat(DEFAULT_DATE_FORMAT);
        try
        {
            return df.parse(dateString);
        }
        catch (ParseException e)
        {
            return new Date();
        }
    }

    /**
     * 按给定参数返回Date对象
     *
     * @param dateTime 时间对象格式为("yyyy-MM-dd HH:mm:ss");
     * @return
     */
    public static Date parseAsDateTime(String dateTime)
    {
        SimpleDateFormat simpledateformat = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT);
        try
        {
            return simpledateformat.parse(dateTime);
        }
        catch (ParseException e)
        {
            return null;
        }
    }

    /**
     * 获取指定日期的开始时间
     * 如：00:00:00
     *
     * @param value
     * @return
     */
    public static Date getDate0000(LocalDateTime value)
    {
        return getDate0000(value.toLocalDate());
    }

    /**
     * 获取指定日期的开始时间
     * 如：00:00:00
     *
     * @param value
     * @return
     */
    public static Date getDate0000(Date value)
    {
        return getDate0000(DateUtils.date2LocalDate(value));
    }

    /**
     * 获取指定日期的开始时间
     * 如：00:00:00
     *
     * @param value
     * @return
     */
    public static Date getDate0000(LocalDate value)
    {
        LocalDateTime todayStart = LocalDateTime.of(value, LocalTime.MIN);
        return DateUtils.localDateTime2Date(todayStart);
    }

    /**
     * 获取指定日期的结束时间
     * 如：23:59:59
     *
     * @param value
     * @return
     */
    public static Date getDate2359(LocalDateTime value)
    {
        return getDate2359(value.toLocalDate());

    }

    /**
     * 获取指定日期的结束时间
     * 如：23:59:59
     *
     * @param value
     * @return
     */
    public static Date getDate2359(Date value)
    {
        return getDate2359(DateUtils.date2LocalDate(value));
    }

    /**
     * 获取指定日期的结束时间
     * 如：23:59:59
     *
     * @param value
     * @return
     */
    public static Date getDate2359(LocalDate value)
    {
        LocalDateTime dateEnd = LocalDateTime.of(value, LocalTime.MAX);
        return DateUtils.localDateTime2Date(dateEnd);
    }

    /**
     * LocalDateTime转换为Date
     *
     * @param localDateTime
     */
    public static Date localDateTime2Date(LocalDateTime localDateTime)
    {
        ZoneId zoneId = ZoneId.systemDefault();
        ZonedDateTime zdt = localDateTime.atZone(zoneId);
        return Date.from(zdt.toInstant());
    }

    //--解析日期 end-----------------------------------------


    /**
     * Date转换为LocalDateTime
     *
     * @param date
     */
    public static LocalDateTime date2LocalDateTime(Date date)
    {
        if (date == null)
        {
            return LocalDateTime.now();
        }
        Instant instant = date.toInstant();
        ZoneId zoneId = ZoneId.systemDefault();
        return instant.atZone(zoneId).toLocalDateTime();
    }

    /**
     * 日期转 LocalDate
     *
     * @param date
     * @return
     */
    public static LocalDate date2LocalDate(Date date)
    {
        if (date == null)
        {
            return LocalDate.now();
        }
        Instant instant = date.toInstant();
        ZoneId zoneId = ZoneId.systemDefault();
        return instant.atZone(zoneId).toLocalDate();
    }

    /**
     * 日期转 LocalTime
     *
     * @param date
     * @return
     */
    public static LocalTime date2LocalTime(Date date)
    {
        if (date == null)
        {
            return LocalTime.now();
        }
        Instant instant = date.toInstant();
        ZoneId zoneId = ZoneId.systemDefault();
        return instant.atZone(zoneId).toLocalTime();
    }

    //-计算日期 start------------------------------------------


    /**
     * 计算结束时间与当前时间中的天数
     *
     * @param endDate 结束日期
     * @return
     */
    public static long until(Date endDate)
    {
        return LocalDateTime.now().until(date2LocalDateTime(endDate), ChronoUnit.DAYS);
    }

    /**
     * 计算结束时间与开始时间中的天数
     *
     * @param startDate 开始日期
     * @param endDate   结束日期
     * @return
     */
    public static long until(Date startDate, Date endDate)
    {
        return date2LocalDateTime(startDate).until(date2LocalDateTime(endDate), ChronoUnit.DAYS);
    }


    /**
     * 计算结束时间与开始时间中的天数
     *
     * @param startDate 开始日期
     * @param endDate   结束日期
     * @return
     */
    public static long until(LocalDateTime startDate, LocalDateTime endDate)
    {
        return startDate.until(endDate, ChronoUnit.DAYS);
    }

    public static long until(LocalDate startDate, LocalDate endDate)
    {
        return startDate.until(endDate, ChronoUnit.DAYS);
    }

    /**
     * 计算2个日期之间的所有的日期 yyyy-MM-dd
     * 含头含尾
     *
     * @param start yyyy-MM-dd
     * @param end   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenDay(Date start, Date end)
    {
        return getBetweenDay(date2LocalDate(start), date2LocalDate(end));
    }

    /**
     * 计算2个日期之间的所有的日期 yyyy-MM-dd
     * 含头含尾
     *
     * @param start yyyy-MM-dd
     * @param end   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenDay(String start, String end)
    {
        return getBetweenDay(LocalDate.parse(start), LocalDate.parse(end));
    }

    /**
     * 计算2个日期之间的所有的日期 yyyy-MM-dd
     * 含头含尾
     *
     * @param startDate yyyy-MM-dd
     * @param endDate   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenDay(LocalDate startDate, LocalDate endDate)
    {
        return getBetweenDay(startDate, endDate, DEFAULT_DATE_FORMAT);
    }

    public static List<String> getBetweenDayEn(LocalDate startDate, LocalDate endDate)
    {
        return getBetweenDay(startDate, endDate, DEFAULT_DATE_FORMAT_EN);
    }

    public static List<String> getBetweenDay(LocalDate startDate, LocalDate endDate, String pattern)
    {
        if (pattern == null)
        {
            pattern = DEFAULT_DATE_FORMAT;
        }
        List<String> list = new ArrayList<>();
        long distance = ChronoUnit.DAYS.between(startDate, endDate);
        if (distance < 1)
        {
            return list;
        }
        String finalPattern = pattern;
        Stream.iterate(startDate, d -> d.plusDays(1)).
                limit(distance + 1)
                .forEach(f -> list.add(f.format(DateTimeFormatter.ofPattern(finalPattern))));
        return list;
    }


    /**
     * 计算2个日期之间的所有的周 yyyy-ww
     * 含头含尾
     *
     * @param start yyyy-MM-dd
     * @param end   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenWeek(Date start, Date end)
    {
        return getBetweenWeek(date2LocalDate(start), date2LocalDate(end));
    }

    /**
     * 计算2个日期之间的所有的周 yyyy-ww
     * 含头含尾
     *
     * @param start yyyy-MM-dd
     * @param end   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenWeek(String start, String end)
    {
        return getBetweenWeek(LocalDate.parse(start), LocalDate.parse(end));
    }

    /**
     * 计算2个日期之间的所有的周 yyyy-ww
     * 含头含尾
     *
     * @param startDate yyyy-MM-dd
     * @param endDate   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenWeek(LocalDate startDate, LocalDate endDate)
    {
        return getBetweenWeek(startDate, endDate, DEFAULT_WEEK_FORMAT);
    }

    public static List<String> getBetweenWeek(LocalDate startDate, LocalDate endDate, String pattern)
    {
        List<String> list = new ArrayList<>();

        long distance = ChronoUnit.WEEKS.between(startDate, endDate);
        if (distance < 1)
        {
            return list;
        }
        Stream.iterate(startDate, d -> d.plusWeeks(1)).
                limit(distance + 1).forEach(f -> list.add(f.format(DateTimeFormatter.ofPattern(pattern))));
        return list;
    }

    /**
     * 计算2个日期之间的所有的月 yyyy-MM
     *
     * @param start yyyy-MM-dd
     * @param end   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenMonth(Date start, Date end)
    {
        return getBetweenMonth(date2LocalDate(start), date2LocalDate(end));
    }

    /**
     * 计算2个日期之间的所有的月 yyyy-MM
     *
     * @param start yyyy-MM-dd
     * @param end   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenMonth(String start, String end)
    {
        return getBetweenMonth(LocalDate.parse(start), LocalDate.parse(end));
    }

    /**
     * 计算2个日期之间的所有的月 yyyy-MM
     *
     * @param startDate yyyy-MM-dd
     * @param endDate   yyyy-MM-dd
     * @return
     */
    public static List<String> getBetweenMonth(LocalDate startDate, LocalDate endDate)
    {
        return getBetweenMonth(startDate, endDate, DEFAULT_MONTH_FORMAT);
    }

    public static List<String> getBetweenMonth(LocalDate startDate, LocalDate endDate, String pattern)
    {
        List<String> list = new ArrayList<>();
        long distance = ChronoUnit.MONTHS.between(startDate, endDate);
        if (distance < 1)
        {
            return list;
        }

        Stream.iterate(startDate, d -> d.plusMonths(1))
                .limit(distance + 1)
                .forEach(f -> list.add(f.format(DateTimeFormatter.ofPattern(pattern))));
        return list;
    }

    /**
     * 计算时间区间内的日期列表，并返回
     *
     * @param startTime
     * @param endTime
     * @param dateList
     * @return
     */
    public static String calculationEn(LocalDateTime startTime, LocalDateTime endTime, List<String> dateList)
    {
        if (startTime == null)
        {
            startTime = LocalDateTime.now();
        }
        if (endTime == null)
        {
            endTime = LocalDateTime.now().plusDays(30);
        }
        return calculationEn(startTime.toLocalDate(), endTime.toLocalDate(), dateList);
    }

    public static String calculation(LocalDate startDate, LocalDate endDate, List<String> dateList)
    {
        if (startDate == null)
        {
            startDate = LocalDate.now();
        }
        if (endDate == null)
        {
            endDate = LocalDate.now().plusDays(30);
        }
        if (dateList == null)
        {
            dateList = new ArrayList<>();
        }
        long day = until(startDate, endDate);

        String dateType = MONTH;
        if (day >= 0 && day <= MAX_MONTH_DAY)
        {
            dateType = DAY;
            dateList.addAll(DateUtils.getBetweenDay(startDate, endDate, DEFAULT_DATE_FORMAT));
        }
        else if (day > MAX_MONTH_DAY && day <= MAX_3_MONTH_DAY)
        {
            dateType = WEEK;
            dateList.addAll(DateUtils.getBetweenWeek(startDate, endDate, DEFAULT_WEEK_FORMAT));
        }
        else if (day > MAX_3_MONTH_DAY && day <= MAX_YEAR_DAY)
        {
            dateType = MONTH;
            dateList.addAll(DateUtils.getBetweenMonth(startDate, endDate, DEFAULT_MONTH_FORMAT));
        }
        else
        {
            throw new BizException("日期参数只能介于0-365天之间");
        }
        return dateType;
    }

    public static String calculationEn(LocalDate startDate, LocalDate endDate, List<String> dateList)
    {
        if (startDate == null)
        {
            startDate = LocalDate.now();
        }
        if (endDate == null)
        {
            endDate = LocalDate.now().plusDays(30);
        }
        if (dateList == null)
        {
            dateList = new ArrayList<>();
        }
        long day = until(startDate, endDate);

        String dateType = MONTH;
        if (day >= 0 && day <= MAX_MONTH_DAY)
        {
            dateType = DAY;
            dateList.addAll(DateUtils.getBetweenDay(startDate, endDate, DEFAULT_DATE_FORMAT_EN));
        }
        else if (day > MAX_MONTH_DAY && day <= MAX_3_MONTH_DAY)
        {
            dateType = WEEK;
            dateList.addAll(DateUtils.getBetweenWeek(startDate, endDate, DEFAULT_WEEK_FORMAT_EN));
        }
        else if (day > MAX_3_MONTH_DAY && day <= MAX_YEAR_DAY)
        {
            dateType = MONTH;
            dateList.addAll(DateUtils.getBetweenMonth(startDate, endDate, DEFAULT_MONTH_FORMAT_EN));
        }
        else
        {
            throw new BizException("日期参数只能介于0-365天之间");
        }
        return dateType;
    }

//----------//----------//----------//----------//----------//----------//----------//----------//----------//----------//----------

}
```







第十五步：编写工具类JwtHelper



```java
package com.example.tools_jwt.utils;

import com.example.tools_jwt.constants.BaseContextConstants;
import com.example.tools_jwt.entity.JwtUserInfo;
import com.example.tools_jwt.entity.Token;
import com.example.tools_jwt.exception.BizException;
import com.example.tools_jwt.exception.ExceptionCode;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Project name(项目名称)：jwt_spring_boot_starter
 * Package(包名): com.example.tools_jwt.utils
 * Class(类名): JwtHelper
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 22:24
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class JwtHelper
{
    private static final RsaKeyHelper RSA_KEY_HELPER = new RsaKeyHelper();

    private static final Logger log = LoggerFactory.getLogger(JwtHelper.class);

    /**
     * 生成用户令牌
     *
     * @param jwtInfo    jwt信息
     * @param priKeyPath 私钥路径
     * @param expire     到期时间
     * @return {@link Token}
     * @throws BizException 业务异常
     */
    public static Token generateUserToken(JwtUserInfo jwtInfo, String priKeyPath, int expire) throws BizException
    {
        JwtBuilder jwtBuilder = Jwts.builder()
                //设置主题
                .setSubject(String.valueOf(jwtInfo.getUserId()))
                .claim(BaseContextConstants.JWT_KEY_ACCOUNT, jwtInfo.getAccount())
                .claim(BaseContextConstants.JWT_KEY_NAME, jwtInfo.getName())
                .claim(BaseContextConstants.JWT_KEY_ORG_ID, jwtInfo.getOrgId())
                .claim(BaseContextConstants.JWT_KEY_STATION_ID, jwtInfo.getStationId());
        return generateToken(jwtBuilder, priKeyPath, expire);
    }


    /**
     * 获取token中的用户信息
     *
     * @param token      令牌
     * @param pubKeyPath 公钥路径
     * @return {@link JwtUserInfo}
     * @throws BizException 业务异常
     */
    public static JwtUserInfo getJwtFromToken(String token, String pubKeyPath) throws BizException
    {
        Jws<Claims> claimsJws = parserToken(token, pubKeyPath);
        Claims body = claimsJws.getBody();
        String strUserId = body.getSubject();
        String account = StrHelper.getObjectValue(body.get(BaseContextConstants.JWT_KEY_ACCOUNT));
        String name = StrHelper.getObjectValue(body.get(BaseContextConstants.JWT_KEY_NAME));
        String strOrgId = StrHelper.getObjectValue(body.get(BaseContextConstants.JWT_KEY_ORG_ID));
        String strDepartmentId = StrHelper.getObjectValue(body.get(BaseContextConstants.JWT_KEY_STATION_ID));
        Long userId = NumberHelper.longValueOf0(strUserId);
        Long orgId = NumberHelper.longValueOf0(strOrgId);
        Long departmentId = NumberHelper.longValueOf0(strDepartmentId);
        return new JwtUserInfo(userId, account, name, orgId, departmentId);
    }


    /**
     * 生成token
     *
     * @param builder    构建器
     * @param priKeyPath 私钥路径
     * @param expire     到期时间
     * @return {@link Token}
     * @throws BizException 业务异常
     */
    protected static Token generateToken(JwtBuilder builder, String priKeyPath, int expire) throws BizException
    {
        try
        {
            //返回的字符串便是我们的jwt串了
            String compactJws = builder.setExpiration(DateUtils.localDateTime2Date(LocalDateTime.now().plusSeconds(expire)))
                    //设置算法（必须）
                    .signWith(SignatureAlgorithm.RS256, RSA_KEY_HELPER.getPrivateKey(priKeyPath))
                    //这个是全部设置完成后拼成jwt串的方法
                    .compact();
            return new Token(compactJws, expire);
        }
        catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            log.error("errcode:{}, message:{}", ExceptionCode.JWT_GEN_TOKEN_FAIL.getCode(), e.getMessage());
            throw new BizException(ExceptionCode.JWT_GEN_TOKEN_FAIL.getCode(), ExceptionCode.JWT_GEN_TOKEN_FAIL.getMsg());
        }
    }


    /**
     * 公钥解析token
     *
     * @param token      令牌
     * @param pubKeyPath 公钥路径
     * @return {@link Jws}<{@link Claims}>
     * @throws BizException 业务异常
     */
    private static Jws<Claims> parserToken(String token, String pubKeyPath) throws BizException
    {
        try
        {
            return Jwts.parser().setSigningKey(RSA_KEY_HELPER.getPublicKey(pubKeyPath)).parseClaimsJws(token);
        }
        catch (ExpiredJwtException ex)
        {
            //过期
            throw new BizException(ExceptionCode.JWT_TOKEN_EXPIRED.getCode(), ExceptionCode.JWT_TOKEN_EXPIRED.getMsg());
        }
        catch (SignatureException ex)
        {
            //签名错误
            throw new BizException(ExceptionCode.JWT_SIGNATURE.getCode(), ExceptionCode.JWT_SIGNATURE.getMsg());
        }
        catch (IllegalArgumentException ex)
        {
            //token 为空
            throw new BizException(ExceptionCode.JWT_ILLEGAL_ARGUMENT.getCode(), ExceptionCode.JWT_ILLEGAL_ARGUMENT.getMsg());
        }
        catch (Exception e)
        {
            log.error("errcode:{}, message:{}", ExceptionCode.JWT_PARSER_TOKEN_FAIL.getCode(), e.getMessage());
            throw new BizException(ExceptionCode.JWT_PARSER_TOKEN_FAIL.getCode(), ExceptionCode.JWT_PARSER_TOKEN_FAIL.getMsg());
        }
    }
}
```







第十六步：
