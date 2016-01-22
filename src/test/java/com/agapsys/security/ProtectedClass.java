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
public class ProtectedClass {
	// CLASS SCOPE =============================================================
	private static void println(String msg, Object...msgArgs) {
			if (msgArgs.length > 0)
				msg = String.format(msg, msgArgs);
			
			System.out.println(msg);
		}
	
	@Secured(requiredRoles = {"ROLE1", "ROLE2"})
	public static void staticFullyProtectedWithArgs(String msg) {
		println("staticFullyProtectedWithArgs(%s)", msg);
	}
	
	@Secured(requiredRoles = {"ROLE1", "ROLE2"})
	public static void staticFullyProtected() {
		println("staticFullyProtected(%s)");
	}
	
	@Secured(requiredRoles = "ROLE1")
	public static void staticProtected() {
		println("staticProtected()");
	}
		
	@Secured
	public static void staticUnprotectedWithAnnotation() {
		println("staticUnprotectedWithAnnotation()");
	}
	
	public static void staticUnprotected() {
		println("staticUnprotected()");
	}
	
	public static void staticChainProtected() {
		staticProtected();
	}
	// =========================================================================
	
	// INSTANCE SCOPE ==========================================================
	@Secured(requiredRoles = {"ROLE1", "ROLE2"})
	public void fullyProtectedWithArgs(String msg) {
		println("fullyProtectedWithArgs(%s)", msg);
	}
	
	@Secured(requiredRoles = {"ROLE1", "ROLE2"})
	public void fullyProtected() {
		println("fullyProtected(%s)");
	}
	
	@Secured(requiredRoles = "ROLE1")
	public void protectedMethod() {
		println("protectedMethod()");
	}
	
	@Secured
	public void unprotectedWithAnnotation() {
		println("unprotectedWithAnnotation");
	}
	
	public void unprotected() {
		println("unprotected()");
	}
	
	public void chainProtected() {
		protectedMethod();
	}
	// =========================================================================
}
