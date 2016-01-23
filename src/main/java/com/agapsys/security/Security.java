/*
 * Copyright 2016 Agapsys Tecnologia Ltda-ME.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.agapsys.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedHashSet;
import java.util.Set;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

/**
 * Class responsible by security preventing unexpected method executions
 *
 * @author Leandro Oliveira (leandro@agapsys.com)
 */
public class Security {

	// CLASS SCOPE =============================================================	
	private static final String EMBEDDED_PROTECTED_CLASS_LIST_FILE = "META-INF/security.lst";
	private static final String EMBEDDED_PROTECTED_CLASS_LIST_FILE_ENCODING = "utf-8";

	// Core functionality ------------------------------------------------------
	protected static boolean allowMultipleInitialization = false;
	protected static boolean ignoreDuplicateRoles = false;
	
	private static void init(SecurityManager securityManager, Set<String> protectedClassNames) {
		if (allowMultipleInitialization || !isRunning()) {
			Security.securityManager = securityManager;

			if (securityManager != null) {
				ClassPool cp = ClassPool.getDefault();

				for (String protectedClassName : protectedClassNames) {
					protectClass(cp, protectedClassName);
				}
			}

			started = true;
		} else {
			throw new IllegalStateException("Framework is already running");
		}
	}

	private static Set<String> getProtectedClassNames(InputStream is, String encoding) {
		try {
			BufferedReader in = new BufferedReader(new InputStreamReader(is, encoding));
			Set<String> nameSet = new LinkedHashSet<>();
			String readLine;

			while ((readLine = in.readLine()) != null) {
				readLine = readLine.trim();
				
				if (readLine.isEmpty())
					continue;
				
				if (!nameSet.add(readLine)) {
					throw new RuntimeException("Duplicate definition of " + readLine);
				}
			}

			return nameSet;
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static Set<String> getEmbeddedProtectedClassNames(String embeddedFileName, String encoding) {
		try (InputStream is = Security.class.getClassLoader().getResourceAsStream(embeddedFileName)) {
			if (is != null)
				return getProtectedClassNames(is, encoding);
			
			return new LinkedHashSet<>();
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static String toScCommaDelimited(Iterable<String>strIterable, boolean encloseInDoubleQuotes) {
		StringBuilder sb = new StringBuilder();

		boolean first = true;
		for (String str : strIterable) {
			if (!first) {
				sb.append(", ");
			}
			
			if (encloseInDoubleQuotes)
				sb.append("\"");
			
			sb.append(str);
			
			if (encloseInDoubleQuotes)
				sb.append("\"");
			
			first = false;
		}

		return sb.toString();
	}

	private static void protectClass(ClassPool cp, String className) {
		try {
			
			CtClass cc = cp.get(className);
			CtMethod methods[] = cc.getDeclaredMethods();
			Secured classSecured = (Secured) cc.getAnnotation(Secured.class);

			for (CtMethod method : methods) {
				Secured methodSecured = (Secured) method.getAnnotation(Secured.class);
				
				if (classSecured != null || methodSecured != null) {
					Set<String> roles = new LinkedHashSet<>();
										
					if (classSecured != null) {
						for (String role : classSecured.value()) {
							if (!roles.add(role) && !ignoreDuplicateRoles)
								throw new RuntimeException(String.format("Duplicate role definition (%s) for %s", role, cc.getName()));
						}
					}
					
					if (methodSecured != null) {
						for (String role : methodSecured.value()) {
							if (!roles.add(role) && !ignoreDuplicateRoles)
								throw new RuntimeException(String.format("Duplicate role definition (%s) for %s", role, method.getLongName()));
						}
					}
					
					String scVarRoles = roles.isEmpty() ? "String[] roles = new String[0]" : String.format("String[] roles = {%s}", toScCommaDelimited(roles, true));
					String scVarSecurityManager = "com.agapsys.security.SecurityManager sm = com.agapsys.security.Security.getSecurityManager()";
					String sc = String.format("{ %s; %s; if (!sm.isAllowed(roles)) { sm.onNotAllowed(); return; } }", scVarRoles, scVarSecurityManager);
					method.insertBefore(sc);
				}
			}
			
			cc.toClass();
		} catch (Throwable t) {
			if (t instanceof RuntimeException) {
				throw (RuntimeException) t;
			}

			throw new RuntimeException(t);
		}
	}
	// -------------------------------------------------------------------------

	private static boolean started = false;
	private static SecurityManager securityManager = null;

	/**
	 * Returns a boolean indicating if security framework is running
	 *
	 * @return a boolean indicating if security framework is running
	 */
	public static boolean isRunning() {
		return started;
	}

	/**
	 * Returns the {@linkplain SecurityManager} instance used by framework.
	 *
	 * @return the {@linkplain SecurityManager} instance used by framework.
	 * @throws IllegalStateException if framework is not running (see
	 * {@linkplain Security#isRunning()})
	 */
	public static SecurityManager getSecurityManager() throws IllegalStateException {
		if (!isRunning()) {
			throw new IllegalStateException("Security is not running");
		}

		return securityManager;
	}

	/**
	 * Initializes security framework
	 *
	 * @param securityManager security framework to be used. Passing
	 * <code>null</code> implies in no security.
	 * @throws IllegalStateException if framework is already running.
	 */
	public static void init(SecurityManager securityManager) throws IllegalStateException {
		init(securityManager, getEmbeddedProtectedClassNames(EMBEDDED_PROTECTED_CLASS_LIST_FILE, EMBEDDED_PROTECTED_CLASS_LIST_FILE_ENCODING));
	}

	public static void init(SecurityManager securityManager, String... protectedClassNames) {
		Set<String> protectedClassNameSet = new LinkedHashSet<>();
		
		for (int i = 0; i < protectedClassNames.length; i++) {
			String protectedClassName = protectedClassNames[i];
			
			if (protectedClassName == null || protectedClassName.trim().isEmpty())
				throw new IllegalArgumentException("Null/Empty class name at index " + i);
			
			protectedClassName = protectedClassName.trim();
			if (!protectedClassNameSet.add(protectedClassName))
				throw new IllegalArgumentException("Duplicate definition of " + protectedClassName);
		}

		init(securityManager, protectedClassNameSet);
	}

	// =========================================================================
	// INSTANCE SCOPE ==========================================================
	protected Security() {
	}
	// =========================================================================
}
