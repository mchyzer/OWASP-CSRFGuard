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
package org.owasp.csrfguard.tag;

import org.owasp.csrfguard.CsrfGuard;

/**
 * expression language functions for JSP
 * @author mchyzer
 */
public class CsrfFunctions {

	/**
	 * 
	 */
	public CsrfFunctions() {
	}

	/**
	 * Print out a token name=value for use in params of a URL. Note, this is
	 * for token per session. For token per page use tokenForUri
	 * 
	 * @return print out token
	 */
	public static String token() {
		return TokenTag.token(null);
	}

	/**
	 * Print out a token name=value for use in params of a URL. Note, this is
	 * for token per page. For token per session use token
	 * @param uri is the uri this token is for
	 * @return token for uri
	 */
	public static String tokenForUri(String uri) {
		return TokenTag.token(uri);
	}

	/**
	 * print out a token name
	 * 
	 * @return token name
	 */
	public static String tokenName() {
		return CsrfGuard.getInstance().getTokenName();
	}

	/**
	 * Print out a token value for use in params of a URL. Note, this is for
	 * token per session. For token per page use tokenValueForUri
	 * 
	 * @return token value
	 */
	public static String tokenValue() {
		return TokenValueTag.tokenValue(null);
	}

	/**
	 * Print out a token value for use in params of a URL. Note, this is for
	 * token per page. For token per session use tokenValue
	 * 
	 * @param uri
	 * @return the token value
	 */
	public static String tokenValueForUri(String uri) {
		return TokenValueTag.tokenValue(uri);
	}

}
