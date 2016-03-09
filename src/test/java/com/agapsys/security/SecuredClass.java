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

/**
 *
 * @author Leandro Oliveira (leandro@agapsys.com)
 */
@Secured("CLASS_ROLE")
public class SecuredClass {

	// CLASS SCOPE =============================================================
	@Secured
	public static class InnerStaticClass {
		@Secured("ROLE")
		public static void staticSecured() {
			println("staticSecured()");
		}
	}
	
	@Unsecured
	private static void println(String msg, Object... msgArgs) {
		if (msgArgs.length > 0) {
			msg = String.format(msg, msgArgs);
		}

		System.out.println(msg);
	}

	@Secured("ROLE")
	private static void privateStaticSecured() {
		println("privateStaticSecured()");
	}

	@Secured("ROLE")
	public static void staticSecuredWithArgs(String msg) {
		println("staticSecuredWithArgs(%s)", msg);
	}

	@Secured("ROLE")
	public static void staticSecured() {
		println("staticSecured()");
	}

	@Secured
	public static void staticSecured2() {
		println("staticSecured2()");
	}

	public static void staticImplicitSecured() {
		println("staticImplicitSecured()");
	}

	public static void staticChainSecured() {
		privateStaticSecured();
		staticSecured();
	}
	// =========================================================================

	// INSTANCE SCOPE ==========================================================
	class InnerClass {
		@Secured("ROLE")
		public void secured() {
			println("secured()");
		}
	}
	
	@Secured("ROLE")
	public void securedWithArgs(String msg) {
		println("securedWithArgs(%s)", msg);
	}

	@Secured("ROLE")
	public void secured() {
		println("secured()");
	}

	@Secured
	public void secured2() {
		println("secured2()");
	}

	public void implicitSecured() {
		println("implicitSecured()");
	}

	public void chainSecured() {
		secured();
	}
	
	@Unsecured
	public void unsecured() {
		println("unsecured()");
	}
	// =========================================================================
}
