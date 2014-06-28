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

import java.io.*;

import org.owasp.csrfguard.*;

public final class TokenTag extends AbstractUriTag {

	private final static long serialVersionUID = 0x12164baa;

	/**
	 * get a token name value pair separated by = (could be for a uri)
	 * @param uri
	 * @return the name value pair 
	 */
	public static String token(String uri) {
	  
		CsrfGuard csrfGuard = CsrfGuard.getInstance();
		String tokenName = csrfGuard.getTokenName();

		String tokenValue = TokenValueTag.tokenValue(uri);

		return tokenName + "=" + tokenValue;

	}

	@Override
	public int doStartTag() {

		String token = token(this.getUri());

		String tokenNameValuePair = token(this.getUri());
		try {
			pageContext.getOut().write(tokenNameValuePair);
		} catch (IOException e) {
			pageContext.getServletContext().log(e.getLocalizedMessage(), e);
		}

		return SKIP_BODY;
	}
	
}
