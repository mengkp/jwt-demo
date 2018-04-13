package jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @auther mengkp
 * @date 2018/4/13
 * @description
 */
public class JwtToken {
    /**
     * 自定义公用密匙
     */
    public static String SECRET="mengkeping";

    /**
     * 生成token
     * @return
     */
    public static String createToken(){

        Date date=new Date();

        //设置过期时间30min
        Calendar nowTime=Calendar.getInstance();
        nowTime.add(Calendar.MINUTE,30);
        Date expirDate=nowTime.getTime();


        Map<String,Object> map=new HashMap<>();
        map.put("alg","HS256");
        map.put("typ","jwt");
        String token=null;
        try {
            token=JWT.create()
                    .withHeader(map)
                    .withClaim("name","mengkp")
                    .withClaim("age",12)
                    .withIssuedAt(date)
                    .withExpiresAt(expirDate)
                    .sign(Algorithm.HMAC256(SECRET));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


        return token;
    }


    public  static Map<String,Claim> decodeToken(String token)throws Exception{

        JWTVerifier verifier=JWT.require(Algorithm.HMAC256(SECRET)).build();
        DecodedJWT jwt=null;
        try{
           jwt=verifier.verify(token);
        }catch(Exception e){
            throw  new RuntimeException("token过期");
        }
        return jwt.getClaims();
    }


    public static void main(String[] args)throws Exception {
        String token=JwtToken.createToken();
        System.out.println(token);

        Map<String,Claim> map=JwtToken.decodeToken(token);
        System.out.println(map.get("name").asString());
        System.out.println(map.get("age").asInt());


        String errToken="1111.222.444";
        Map<String,Claim> map1=JwtToken.decodeToken(errToken);

    }


}
