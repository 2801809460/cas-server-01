//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.authentication;

import java.io.Serializable;
import javax.validation.constraints.Size;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class UsernamePasswordCredential implements Credential, Serializable {
    public static final String AUTHENTICATION_ATTRIBUTE_PASSWORD = "credential";
    private static final long serialVersionUID = -700605081472810939L;
    @Size(
        min = 1,
        message = "required.username"
    )
    private String username;
    @Size(
        min = 1,
        message = "required.password"
    )
    private String password;

    @Size(
            min = 1,
            message = "required.capcha"
    )
    private String capcha;

    public UsernamePasswordCredential() {
    }

    public UsernamePasswordCredential(String userName, String password) {
        this.username = userName;
        this.password = password;
    }

    public UsernamePasswordCredential(String userName, String password,String capcha) {
        this.username = userName;
        this.password = password;
        this.capcha = capcha;
    }

    public String getCapcha() {
        return capcha;
    }

    public void setCapcha(String capcha) {
        this.capcha = capcha;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String userName) {
        this.username = userName;
    }

    public String getId() {
        return this.username;
    }

    public String toString() {
        return this.username;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o != null && this.getClass() == o.getClass()) {
            UsernamePasswordCredential that = (UsernamePasswordCredential)o;
            if (this.password != null) {
                if (this.password.equals(that.password)) {
                    return this.username != null ? this.username.equals(that.username) : that.username == null;
                }
            } else if (that.password == null) {
                return this.username != null ? this.username.equals(that.username) : that.username == null;
            }

            return false;
        } else {
            return false;
        }
    }

    public int hashCode() {
        return (new HashCodeBuilder()).append(this.username).append(this.password).toHashCode();
    }
}
