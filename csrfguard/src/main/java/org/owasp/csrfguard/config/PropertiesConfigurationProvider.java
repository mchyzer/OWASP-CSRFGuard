/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric@infraredsecurity.com), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard.config;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.ILogger;

/**
 * ConfifgurationProvider based on a java.util.Properties object.
 *
 */
public final class PropertiesConfigurationProvider implements ConfigurationProvider {

	private final static String ACTION_PREFIX = "org.owasp.csrfguard.action.";

	private final static String PROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.protected.";
	
	private final static String UNPROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.unprotected.";

	private final ILogger logger;

	private final String tokenName;

	private final int tokenLength;

	private final boolean rotate;

	private final boolean tokenPerPage;

	private final boolean tokenPerPagePrecreate;

	private final SecureRandom prng;

	private final String newTokenLandingPage;

	private final boolean useNewTokenLandingPage;

	private final boolean ajax;
	
	private final boolean protect;
	
	private final String sessionKey;
	
	private final Set<String> protectedPages;

	private final Set<String> unprotectedPages;

	private final Set<String> protectedMethods;

	private final List<IAction> actions;

	public PropertiesConfigurationProvider(Properties properties) throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, ClassNotFoundException, IOException, NoSuchProviderException {
		actions = new ArrayList<IAction>();
		protectedPages = new HashSet<String>();
		unprotectedPages = new HashSet<String>();
		protectedMethods = new HashSet<String>();
		/** load simple properties **/
		logger = (ILogger) Class.forName(properties.getProperty("org.owasp.csrfguard.Logger", "org.owasp.csrfguard.log.ConsoleLogger")).newInstance();
		tokenName = properties.getProperty("org.owasp.csrfguard.TokenName", "OWASP_CSRFGUARD");
		tokenLength = Integer.parseInt(properties.getProperty("org.owasp.csrfguard.TokenLength", "32"));
		rotate = Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Rotate", "false"));
		tokenPerPage = Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.TokenPerPage", "false"));
		tokenPerPagePrecreate = Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.TokenPerPagePrecreate", "false"));
		prng = SecureRandom.getInstance(properties.getProperty("org.owasp.csrfguard.PRNG", "SHA1PRNG"), properties.getProperty("org.owasp.csrfguard.PRNG.Provider", "SUN"));
		newTokenLandingPage = properties.getProperty("org.owasp.csrfguard.NewTokenLandingPage");

		//default to false if newTokenLandingPage is not set; default to true if set.
		if (newTokenLandingPage == null) {
			useNewTokenLandingPage = Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.UseNewTokenLandingPage", "false"));
		} else {
			useNewTokenLandingPage = Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.UseNewTokenLandingPage", "true"));
		}
		sessionKey = properties.getProperty("org.owasp.csrfguard.SessionKey", "OWASP_CSRFGUARD_KEY");
		ajax = Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Ajax", "false"));
		protect = Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Protect", "false"));

		/** first pass: instantiate actions **/
		Map<String, IAction> actionsMap = new HashMap<String, IAction>();

		for (Object obj : properties.keySet()) {
			String key = (String) obj;

			if (key.startsWith(ACTION_PREFIX)) {
				String directive = key.substring(ACTION_PREFIX.length());
				int index = directive.indexOf('.');

				/** action name/class **/
				if (index < 0) {
					String actionClass = properties.getProperty(key);
					IAction action = (IAction) Class.forName(actionClass).newInstance();

					action.setName(directive);
					actionsMap.put(action.getName(), action);
					actions.add(action);
				}
			}
		}

		/** second pass: initialize action parameters **/
		for (Object obj : properties.keySet()) {
			String key = (String) obj;

			if (key.startsWith(ACTION_PREFIX)) {
				String directive = key.substring(ACTION_PREFIX.length());
				int index = directive.indexOf('.');

				/** action name/class **/
				if (index >= 0) {
					String actionName = directive.substring(0, index);
					IAction action = actionsMap.get(actionName);

					if (action == null) {
						throw new IOException(String.format("action class %s has not yet been specified", actionName));
					}

					String parameterName = directive.substring(index + 1);
					String parameterValue = properties.getProperty(key);

					action.setParameter(parameterName, parameterValue);
				}
			}
		}

		/** ensure at least one action was defined **/
		if (actions.size() <= 0) {
			throw new IOException("failure to define at least one action");
		}

		/** initialize protected, unprotected pages **/
		for (Object obj : properties.keySet()) {
			String key = (String) obj;
			
			if (key.startsWith(PROTECTED_PAGE_PREFIX)) {
				String directive = key.substring(PROTECTED_PAGE_PREFIX.length());
				int index = directive.indexOf('.');

				/** page name/class **/
				if (index < 0) {
					String pageUri = properties.getProperty(key);
					
					protectedPages.add(pageUri);
				}
			}

			if (key.startsWith(UNPROTECTED_PAGE_PREFIX)) {
				String directive = key.substring(UNPROTECTED_PAGE_PREFIX.length());
				int index = directive.indexOf('.');

				/** page name/class **/
				if (index < 0) {
					String pageUri = properties.getProperty(key);
					
					unprotectedPages.add(pageUri);
				}
			}
		}

		/** initialize protected methods **/
		String methodList = properties.getProperty("org.owasp.csrfguard.ProtectedMethods");
		if (methodList != null && methodList.trim().length() != 0) {
			for (String method : methodList.split(",")) {
				protectedMethods.add(method.trim());
			}
		}
	}
	
	public ILogger getLogger() {
		return logger;
	}

	public String getTokenName() {
		return tokenName;
	}

	public int getTokenLength() {
		return tokenLength;
	}

	public boolean isRotateEnabled() {
		return rotate;
	}

	public boolean isTokenPerPageEnabled() {
		return tokenPerPage;
	}

	public boolean isTokenPerPagePrecreateEnabled() {
		return tokenPerPagePrecreate;
	}

	public SecureRandom getPrng() {
		return prng;
	}

	public String getNewTokenLandingPage() {
		return newTokenLandingPage;
	}

	public boolean isUseNewTokenLandingPage() {
		return useNewTokenLandingPage;
	}

	public boolean isAjaxEnabled() {
		return ajax;
	}

	public boolean isProtectEnabled() {
		return protect;
	}

	public String getSessionKey() {
		return sessionKey;
	}

	public Set<String> getProtectedPages() {
		return protectedPages;
	}

	public Set<String> getUnprotectedPages() {
		return unprotectedPages;
	}

	public Set<String> getProtectedMethods () {
		return protectedMethods;
	}

	public List<IAction> getActions() {
		return actions;
	}

}
