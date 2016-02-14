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
 * @author Leandro Oliveira (leandro@agapsys.com)
 */
public class Security {

	// CLASS SCOPE =============================================================	
	private static final String EMBEDDED_PROTECTED_CLASS_LIST_FILE = "META-INF/security.info";
	private static final String EMBEDDED_PROTECTED_CLASS_LIST_FILE_ENCODING = "utf-8";

	// Core functionality ------------------------------------------------------
	private static void init(ClassLoader classLoader, SecurityManager securityManager, Set<String> securedClasses) {
		if (classLoader == null)
			throw new IllegalArgumentException("A class loader must be provided");
		
		if (securityManager == null)
			throw new IllegalArgumentException("A security manager must be provided");
		
		if (securedClasses == null)
			throw new IllegalArgumentException("Secured classes cannot be null");
		
		Security.securityManager = securityManager;

		ClassPool cp = ClassPool.getDefault();

		for (String securedClass : securedClasses) {
			secure(classLoader, cp, securedClass);
		}
	}

	private static Set<String> readSecurityInfo(InputStream is, String encoding) {
		try {
			BufferedReader in = new BufferedReader(new InputStreamReader(is, encoding));
			Set<String> classes = new LinkedHashSet<>();
			String readLine;

			while ((readLine = in.readLine()) != null) {
				readLine = readLine.trim();
				
				if (readLine.isEmpty())
					continue;
				
				if (!classes.add(readLine)) {
					throw new RuntimeException("Duplicate definition of " + readLine);
				}
			}

			return classes;
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static Set<String> readSecurityInfo(String embeddedFileName, String encoding) {
		try (InputStream is = Security.class.getClassLoader().getResourceAsStream(embeddedFileName)) {
			if (is != null)
				return readSecurityInfo(is, encoding);
			
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

	private static boolean logEnabled = false;
	private static boolean skipFrozenClasses = false;
	
	/** 
	 * Enables/Disables console logging output.
	 * @param enable defines if log messages shall be printed to console. By default log is disabled.
	 */
	public static void enableLog(boolean enable) {
		logEnabled = enable;
	}
	
	/**
	 * Defines if frozen classes shall be skipped.
	 * @param skip define if frozen classes shall be skipped instead of rising errors. By default frozen classes are not skipped.
	 */
	public static void skipFrozenClasses(boolean skip) {
		skipFrozenClasses = skip;
	}
	
	private static void log(String message, Object...msgArgs) {
		if (logEnabled) {
			if (msgArgs.length > 0) message = String.format(message, msgArgs);
			System.out.println(message);
		}
	}
	
	private static void secure(ClassLoader classLoader, ClassPool cp, String className) {
		try {
			
			CtClass cc = cp.get(className);
			
			if (!skipFrozenClasses || !cc.isFrozen()) {
				CtMethod methods[] = cc.getDeclaredMethods();
				Secured classSecured = (Secured) cc.getAnnotation(Secured.class);

				for (CtMethod method : methods) {
					Secured methodSecured = (Secured) method.getAnnotation(Secured.class);

					if (classSecured != null || methodSecured != null) {
						Set<String> roles = new LinkedHashSet<>();

						if (classSecured != null) {
							for (String role : classSecured.value()) {
								if (!roles.add(role))
									throw new RuntimeException(String.format("Duplicate role definition (%s) for %s", role, cc.getName()));
							}
						}

						if (methodSecured != null) {
							for (String role : methodSecured.value()) {
								if (!roles.add(role))
									throw new RuntimeException(String.format("Duplicate role definition (%s) for %s", role, method.getLongName()));
							}
						}

						String scVarRoles = roles.isEmpty() ? "String[] roles = new String[0]" : String.format("String[] roles = {%s}", toScCommaDelimited(roles, true));
						String scVarSecurityManager = "com.agapsys.security.SecurityManager sm = com.agapsys.security.Security.getSecurityManager()";
						String sc = String.format("{ %s; %s; if (!sm.isAllowed(roles)) { sm.onNotAllowed(); } }", scVarRoles, scVarSecurityManager);
						method.insertBefore(sc);
					}
				}
			
				cc.toClass(classLoader, Security.class.getProtectionDomain());
				log("Secured class: %s", className);
			} else {
				log("Class already secured: %s", className);
			}
		} catch (Throwable t) {
			if (t instanceof RuntimeException) {
				throw (RuntimeException) t;
			}

			throw new RuntimeException(t);
		}
	}
	// -------------------------------------------------------------------------

	private static SecurityManager securityManager = null;

	/**
	 * Returns the {@linkplain SecurityManager} instance used by framework.
	 *
	 * @return the {@linkplain SecurityManager} instance used by framework.
	 * @throws IllegalStateException if framework is not running (see
	 * {@linkplain Security#isRunning()})
	 */
	public static SecurityManager getSecurityManager() throws IllegalStateException {
		return securityManager;
	}

	/**
	 * Initializes security framework
	 *
	 * @param securityManager security framework to be used. Passing
	 * <code>null</code> implies in no security.
	 * @throws IllegalStateException if framework is already running.
	 */
	protected static void init(SecurityManager securityManager) {
		init(Security.class.getClassLoader(), securityManager);
	}
	
	protected static void init(ClassLoader classLoader, SecurityManager securityManager) {
		init(classLoader, securityManager, readSecurityInfo(EMBEDDED_PROTECTED_CLASS_LIST_FILE, EMBEDDED_PROTECTED_CLASS_LIST_FILE_ENCODING));
	}

	protected static void init(SecurityManager securityManager, String... securedClasses) {
		init(Security.class.getClassLoader(), securityManager, securedClasses);
	}
	
	protected static void init(ClassLoader classLoader, SecurityManager securityManager, String... securedClasses) {
		Set<String> protectedClassNameSet = new LinkedHashSet<>();
		
		for (int i = 0; i < securedClasses.length; i++) {
			String protectedClassName = securedClasses[i];
			
			if (protectedClassName == null || protectedClassName.trim().isEmpty())
				throw new IllegalArgumentException("Null/Empty class name at index " + i);
			
			protectedClassName = protectedClassName.trim();
			if (!protectedClassNameSet.add(protectedClassName))
				throw new IllegalArgumentException("Duplicate definition of " + protectedClassName);
		}

		init(classLoader, securityManager, protectedClassNameSet);
	}
	// =========================================================================
	
	// INSTANCE SCOPE ==========================================================
	protected Security() {}
	// =========================================================================
}
