

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



