package com.example.jwt.security.v5.service;

import com.example.jwt.security.v5.configuration.MyMethodSecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SecurityCheckService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityCheckService.class);

    @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE')")
    public String preAuthorize() {
        return "@PreAuthorize(\"hasAuthority('ADMIN_PRIVILEGE')\")";
    }

    /**
     * {@link MyMethodSecurityConfig#customMethodSecurityMetadataSource()} register custom method security metadata source
     *
     * @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE')")
     */
    public String customMethodSecurityMetadataSource() {
        return "CustomMethodSecurityConfiguration#metadataSource.customMethodSecurityMetadataSource()#addSecureMethod(SecurityExampleService.class, \"customMethodSecurityMetadataSource\", SecurityConfig.createList(\"ADMIN_PRIVILEGE\"));";
    }

    /**
     * 表示在方法执行之后执行，而且可以调用方法的返回值，然后对返回值进行过滤、处理或者修改，并且返回。EL变量returnObject表示返回的对象。方法需要返回集合或者数组
     *
     * @return [ "Item2", "Item4" ] for USER_PRIVILEGE and return EMPTY [] for CLIENT_PRIVILEGE
     */
    @PostFilter("((filterObject.contains('2') or filterObject.contains('4')) and hasAuthority('USER_PRIVILEGE')) or hasAuthority('ADMIN_PRIVILEGE')")
    public List<String> postFilter() {
        List<String> list = new ArrayList<>();
        for (int index = 0; index < 10; index++) {
            list.add("Item" + index);
        }
        return list;
    }

}
