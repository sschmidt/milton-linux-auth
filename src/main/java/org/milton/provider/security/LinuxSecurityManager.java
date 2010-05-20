/**
   Copyright 2010 Sebastian Schmidt

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package org.milton.provider.security;

import net.sf.jpam.Pam;

import com.bradmcevoy.http.Auth;
import com.bradmcevoy.http.Request;
import com.bradmcevoy.http.Resource;
import com.bradmcevoy.http.SecurityManager;
import com.bradmcevoy.http.Request.Method;
import com.bradmcevoy.http.http11.auth.DigestResponse;

/**
 * A Milton SecurityManager based on the JPAM-API
 * 
 * @author Sebastian Schmidt <mail@schmidt-seb.de>
 */
public class LinuxSecurityManager implements SecurityManager {

	private String realm;

	public LinuxSecurityManager(String realm) {
		this.realm = realm;
	}

	@Override
	public Object authenticate(DigestResponse digest) {
		throw new IllegalStateException("Not yet supported");
	}

	@Override
	public Object authenticate(String userName, String password) {
		Pam pam = new Pam();
		boolean authenticated = pam.authenticateSuccessful(userName, password);

		if (authenticated) {
			return userName;
		}

		return null;
	}

	@Override
	public boolean authorise(Request request, Method method, Auth auth,
			Resource resource) {
		return auth != null && auth.getTag() != null;
	}

	@Override
	public String getRealm(String host) {
		return realm;
	}
}
