package com.qianfeng.weixin.controller;

import com.qianfeng.weixin.util.SHA1;
import com.sun.org.apache.xml.internal.security.keys.storage.implementations.CertsInFilesystemDirectoryResolver;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.TreeSet;

/**
 * 跟微信服務器交互
 */
@Controller
@RequestMapping("weixin")
public class WeixinController {

    private static final String TOKEN = "panxyToken";

//    @RequestMapping(value = "authentication",method = RequestMethod.GET)
    @GetMapping("authentication")
    @ResponseBody
    public String authentication(HttpServletRequest request){
        //做微信接口认证
        //微信服务器会自动调用我们自己做的接口，做认证
        //获取微信发给我们的参数
        String signature = request.getParameter("signature");
        String timestamp = request.getParameter("timestamp");
        String nonce = request.getParameter("nonce");
        String echostr = request.getParameter("echostr");

        //1.将token、timestamp、nonce三个参数进行字典序排序
        TreeSet<String> treeSet= new TreeSet();
        treeSet.add(TOKEN);
        treeSet.add(timestamp);
        treeSet.add(nonce);
        //2.将三个参数字符串拼接成一个字符串进行shal加密
        StringBuilder stringBuilder = new StringBuilder();
        for (String s : treeSet) {
            stringBuilder.append(s);
        }
        //sha1 摘要算法
        String encode = SHA1.encode(stringBuilder.toString());
        //3.开发者获得加密后的字符串可与signature对比，标识该请求来源于微信
        if(encode.equals(signature)){
            System.out.println("微信平台发送过来的认证请求");
            return echostr;
        }else{
            System.out.println("非微信平台发送过来的认证请求");
            return "failed";
        }

    }
}
