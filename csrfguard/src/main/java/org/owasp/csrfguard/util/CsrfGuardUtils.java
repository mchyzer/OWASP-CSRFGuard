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
package org.owasp.csrfguard.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

/**
 *
 */
public class CsrfGuardUtils {

	/**
	 * for a url, get the protocol and domain, e.g. for url https://a.b/path, will return https://a.b
	 * @param url
	 * @return the protocol and path
	 */
	public static String httpProtocolAndDomain(String url) {
		int firstSlashAfterProtocol = url.indexOf('/', 8);
		if (firstSlashAfterProtocol < 0) {
			//must not have a path
			return url;
		}

		return url.substring(0, firstSlashAfterProtocol);
	}

	/**
	 * helper method for calling a method with no params (could be in
	 * superclass)
	 *
	 * @param theClass
	 *            the class which has the method
	 * @param invokeOn
	 *            to call on or null for static
	 * @param methodName
	 *            method name to call
	 * @return the data
	 */
	public static Object callMethod(Class theClass, Object invokeOn,
			String methodName) {
		return callMethod(theClass, invokeOn, methodName, null, null);
	}

	/**
	 * helper method for calling a method (could be in superclass)
	 *
	 * @param theClass
	 *            the class which has the method
	 * @param invokeOn
	 *            to call on or null for static
	 * @param methodName
	 *            method name to call
	 * @param paramTypesOrArrayOrList
	 *            types of the params
	 * @param paramsOrListOrArray
	 *            data
	 * @return the data
	 */
	public static Object callMethod(Class theClass, Object invokeOn,
			String methodName, Object paramTypesOrArrayOrList,
			Object paramsOrListOrArray) {
		return callMethod(theClass, invokeOn, methodName,
				paramTypesOrArrayOrList, paramsOrListOrArray, true);
	}

	/**
	 * helper method for calling a method
	 *
	 * @param theClass
	 *            the class which has the method
	 * @param invokeOn
	 *            to call on or null for static
	 * @param methodName
	 *            method name to call
	 * @param paramTypesOrArrayOrList
	 *            types of the params
	 * @param paramsOrListOrArray
	 *            data
	 * @param callOnSupers
	 *            if static and method not exists, try on supers
	 * @return the data
	 */
	public static Object callMethod(Class theClass, Object invokeOn,
			String methodName, Object paramTypesOrArrayOrList,
			Object paramsOrListOrArray, boolean callOnSupers) {
		return callMethod(theClass, invokeOn, methodName,
				paramTypesOrArrayOrList, paramsOrListOrArray, callOnSupers,
				false);
	}

	/**
	 * helper method for calling a method
	 *
	 * @param theClass
	 *            the class which has the method
	 * @param invokeOn
	 *            to call on or null for static
	 * @param methodName
	 *            method name to call
	 * @param paramTypesOrArrayOrList
	 *            types of the params
	 * @param paramsOrListOrArray
	 *            data
	 * @param callOnSupers
	 *            if static and method not exists, try on supers
	 * @param overrideSecurity
	 *            true to call on protected or private etc methods
	 * @return the data
	 */
	public static Object callMethod(Class theClass, Object invokeOn,
			String methodName, Object paramTypesOrArrayOrList,
			Object paramsOrListOrArray, boolean callOnSupers,
			boolean overrideSecurity) {
		try {
			Method method = null;

			Class[] paramTypesArray = (Class[]) toArray(paramTypesOrArrayOrList);

			try {
				method = theClass.getDeclaredMethod(methodName, paramTypesArray);
				if (overrideSecurity) {
					method.setAccessible(true);
				}
			} catch (Exception e) {
				// if method not found
				if (e instanceof NoSuchMethodException) {
					// if traversing up, and not Object, and not instance method
					// CH 070425 not sure why invokeOn needs to be null, removing
					// this
					if (callOnSupers /* && invokeOn == null */
							&& !theClass.equals(Object.class)) {
						return callMethod(theClass.getSuperclass(), invokeOn,
								methodName, paramTypesOrArrayOrList,
								paramsOrListOrArray, callOnSupers, overrideSecurity);
					}
				}
				throw new RuntimeException("Problem calling method " + methodName
						+ " on " + theClass.getName(), e);
			}

			return invokeMethod(method, invokeOn, paramsOrListOrArray);
		} catch (RuntimeException re) {
			String message = "Problem calling method " + methodName
					+ " on " + (theClass == null ? null : theClass.getName());
			if (injectInException(re, message)) {
				throw re;
			}
			throw new RuntimeException(message, re);
		}
	}


	/**
	 * <pre>Returns the class object.</pre>
	 * @param origClassName is fully qualified
	 * @return the class
	 */
	public static Class forName(String origClassName) {

		try {
			return Class.forName(origClassName);
		} catch (Throwable t) {
			throw new RuntimeException("Problem loading class: " + origClassName, t);
		}

	}

	public static String getInitParameter(ServletConfig servletConfig, String name, 
			String configFileDefaultParamValue, String defaultValue) {
		String value = servletConfig.getInitParameter(name);

		if (value == null || "".equals(value.trim())) {
			value = configFileDefaultParamValue;
		}

		if (value == null || "".equals(value.trim())) {
			value = defaultValue;
		}

		return value;
	}

	public static String readResourceFileContent(String resourceName) {
		InputStream is = null;

		try {
			is = CsrfGuardUtils.class.getClassLoader().getResourceAsStream(resourceName);
			if(is == null) {
				throw new IllegalStateException("Could not find resource " + resourceName);
			}
			return readInputStreamContent(is);
		} finally {
			Streams.close(is);
		}
	}
	public static String readFileContent(String fileName) {
		InputStream is = null;

		try {
			is = new FileInputStream(fileName);
			return readInputStreamContent(is);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		} finally {
			Streams.close(is);
		}
	}
	public static String readInputStreamContent(InputStream is) {
		StringBuilder sb = new StringBuilder();

		try {
			int i;

			while ((i = is.read()) > 0) {
				sb.append((char) i);
			}
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		return sb.toString();
	}

	/**
	 * If we can, inject this into the exception, else return false
	 * @param t
	 * @param message
	 * @return true if success, false if not
	 */
	public static boolean injectInException(Throwable t, String message) {

		//this is the field for sun java 1.5
		String throwableFieldName = "detailMessage";

		try {
			String currentValue = t.getMessage();
			if (!isBlank(currentValue)) {
				currentValue += ",\n" + message;
			} else {
				currentValue = message;
			}
			assignField(t, throwableFieldName, currentValue);
			return true;
		} catch (Throwable t2) {
			//dont worry about what the problem is, return false so the caller can log
			return false;
		}

	}

	/**
	 * See if the input is null or if string, if it is empty or blank (whitespace)
	 * @param input
	 * @return true if blank
	 */
	public static boolean isBlank(Object input) {
		if (null == input) {
			return true;
		}
		return (input instanceof String && isBlank((String)input));
	}

	/**
	 * <p>Checks if a String is whitespace, empty ("") or null.</p>
	 *
	 * <pre>
	 * isBlank(null)      = true
	 * isBlank("")        = true
	 * isBlank(" ")       = true
	 * isBlank("bob")     = false
	 * isBlank("  bob  ") = false
	 * </pre>
	 *
	 * @param str  the String to check, may be null
	 * @return <code>true</code> if the String is null, empty or whitespace
	 * @since 2.0
	 */
	public static boolean isBlank(String str) {
		int strLen;
		if (str == null || (strLen = str.length()) == 0) {
			return true;
		}
		for (int i = 0; i < strLen; i++) {
			if ((Character.isWhitespace(str.charAt(i)) == false)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * assign data to a field
	 *
	 * @param theClass
	 *            the class which has the method
	 * @param invokeOn
	 *            to call on or null for static
	 * @param fieldName
	 *            method name to call
	 * @param dataToAssign
	 *            data
	 * @param callOnSupers
	 *            if static and method not exists, try on supers
	 * @param overrideSecurity
	 *            true to call on protected or private etc methods
	 * @param typeCast
	 *            true if we should typecast
	 * @param annotationWithValueOverride
	 *            annotation with value of override
	 */
	public static void assignField(Class theClass, Object invokeOn,
			String fieldName, Object dataToAssign, boolean callOnSupers,
			boolean overrideSecurity, boolean typeCast,
			Class<? extends Annotation> annotationWithValueOverride) {
		if (theClass == null && invokeOn != null) {
			theClass = invokeOn.getClass();
		}
		Field field = field(theClass, fieldName, callOnSupers, true);
		assignField(field, invokeOn, dataToAssign, overrideSecurity, typeCast,
				annotationWithValueOverride);
	}

	/**
	 * Convert a list to an array with the type of the first element e.g. if it
	 * is a list of Person objects, then the array is Person[]
	 *
	 * @param objectOrArrayOrCollection
	 *            is a list
	 * @return the array of objects with type of the first element in the list
	 */
	public static Object toArray(Object objectOrArrayOrCollection) {
		// do this before length since if array with null in it, we want ti get
		// it back
		if (objectOrArrayOrCollection != null
				&& objectOrArrayOrCollection.getClass().isArray()) {
			return objectOrArrayOrCollection;
		}
		int length = length(objectOrArrayOrCollection);
		if (length == 0) {
			return null;
		}

		if (objectOrArrayOrCollection instanceof Collection) {
			Collection collection = (Collection) objectOrArrayOrCollection;
			Object first = collection.iterator().next();
			return toArray(collection, first == null ? Object.class : first
					.getClass());
		}
		// make an array of the type of object passed in, size one
		Object array = Array.newInstance(objectOrArrayOrCollection.getClass(),
				1);
		Array.set(array, 0, objectOrArrayOrCollection);
		return array;
	}

	/**
	 * Null safe array length or map
	 *
	 * @param arrayOrCollection
	 * @return the length of the array (0 for null)
	 */
	public static int length(Object arrayOrCollection) {
		if (arrayOrCollection == null) {
			return 0;
		}
		if (arrayOrCollection.getClass().isArray()) {
			return Array.getLength(arrayOrCollection);
		}
		if (arrayOrCollection instanceof Collection) {
			return ((Collection) arrayOrCollection).size();
		}
		if (arrayOrCollection instanceof Map) {
			return ((Map) arrayOrCollection).size();
		}
		// simple non array non collection object
		return 1;
	}

	/**
	 * convert a list into an array of type of theClass
	 * @param <T> is the type of the array
	 * @param collection list to convert
	 * @param theClass type of array to return
	 * @return array of type theClass[] filled with the objects from list
	 */
	@SuppressWarnings("unchecked")
	public static <T> T[] toArray(Collection collection, Class<T> theClass) {
		if (collection == null || collection.size() == 0) {
			return null;
		}

		return (T[])collection.toArray((Object[]) Array.newInstance(theClass,
				collection.size()));

	}

	/**
	 * assign data to a field. Will find the field in superclasses, will
	 * typecast, and will override security (private, protected, etc)
	 *
	 * @param invokeOn
	 *            to call on or null for static
	 * @param fieldName
	 *            method name to call
	 * @param dataToAssign
	 *            data
	 */
	public static void assignField(Object invokeOn, String fieldName,
			Object dataToAssign) {
		assignField(null, invokeOn, fieldName, dataToAssign, true, true, true,
				null);
	}

	/** pass this in the invokeOn to signify no params */
	private static final Object NO_PARAMS = new Object();

	/**
	 * Safely invoke a reflection method that takes no args
	 *
	 * @param method
	 *            to invoke
	 * @param invokeOn
	 * if NO_PARAMS then will not pass in params.
	 * @return the result
	 */
	public static Object invokeMethod(Method method, Object invokeOn) {
		return invokeMethod(method, invokeOn, NO_PARAMS);
	}

	/**
	 * Safely invoke a reflection method
	 *
	 * @param method
	 *            to invoke
	 * @param invokeOn
	 * @param paramsOrListOrArray must be an arg.  If null, will pass null.
	 * if NO_PARAMS then will not pass in params.
	 * @return the result
	 */
	public static Object invokeMethod(Method method, Object invokeOn,
			Object paramsOrListOrArray) {

		Object[] args = paramsOrListOrArray == NO_PARAMS ? null : (Object[]) toArray(paramsOrListOrArray);

		//we want to make sure things are accessible
		method.setAccessible(true);

		//only if the method exists, try to execute
		Object result = null;
		Exception e = null;
		try {
			result = method.invoke(invokeOn, args);
		} catch (IllegalAccessException iae) {
			e = iae;
		} catch (IllegalArgumentException iae) {
			e = iae;
		} catch (InvocationTargetException ite) {
			//this means the underlying call caused exception... its ok if runtime
			if (ite.getCause() instanceof RuntimeException) {
				throw (RuntimeException)ite.getCause();
			}
			//else throw as invocation target...
			e = ite;
		}
		if (e != null) {
			throw new RuntimeException("Cant execute reflection method: "
					+ method.getName() + ", on: " + className(invokeOn)
					+ ", with args: " + classNameCollection(args), e);
		}
		return result;
	}

	/**
	 * null safe classname method, gets the unenhanced name
	 *
	 * @param object
	 * @return the classname
	 */
	public static String className(Object object) {
		return object == null ? null : object.getClass()
				.getName();
	}

	/**
	 * null safe classname method, max out at 20
	 *
	 * @param object
	 * @return the classname
	 */
	public static String classNameCollection(Object object) {
		if (object == null) {
			return null;
		}
		StringBuffer result = new StringBuffer();

		Iterator iterator = iterator(object);
		int length = length(object);
		for (int i = 0; i < length && i < 20; i++) {
			result.append(className(next(object, iterator, i)));
			if (i != length - 1) {
				result.append(", ");
			}
		}
		return result.toString();
	}

	/**
	 * null safe iterator getter if the type if collection
	 *
	 * @param collection
	 * @return the iterator
	 */
	public static Iterator iterator(Object collection) {
		if (collection == null) {
			return null;
		}
		// array list doesnt need an iterator
		if (collection instanceof Collection
				&& !(collection instanceof ArrayList)) {
			return ((Collection) collection).iterator();
		}
		return null;
	}

	/**
	 * If array, get the element based on index, if Collection, get it based on
	 * iterator.
	 *
	 * @param arrayOrCollection
	 * @param iterator
	 * @param index
	 * @return the object
	 */
	public static Object next(Object arrayOrCollection, Iterator iterator,
			int index) {
		if (arrayOrCollection.getClass().isArray()) {
			return Array.get(arrayOrCollection, index);
		}
		if (arrayOrCollection instanceof ArrayList) {
			return ((ArrayList) arrayOrCollection).get(index);
		}
		if (arrayOrCollection instanceof Collection) {
			return iterator.next();
		}
		// simple object
		if (0 == index) {
			return arrayOrCollection;
		}
		throw new RuntimeException("Invalid class type: "
				+ arrayOrCollection.getClass().getName());
	}

	/**
	 * assign data to a field
	 *
	 * @param field
	 *            is the field to assign to
	 * @param invokeOn
	 *            to call on or null for static
	 * @param dataToAssign
	 *            data
	 * @param overrideSecurity
	 *            true to call on protected or private etc methods
	 * @param typeCast
	 *            true if we should typecast
	 * @param annotationWithValueOverride
	 *            annotation with value of override, or null if none
	 */
	@SuppressWarnings("unchecked")
	public static void assignField(Field field, Object invokeOn,
			Object dataToAssign, boolean overrideSecurity, boolean typeCast,
			Class<? extends Annotation> annotationWithValueOverride) {

		if (annotationWithValueOverride != null) {
			// see if in annotation
			Annotation annotation = field
					.getAnnotation(annotationWithValueOverride);
			if (annotation != null) {

				// type of the value, or String if not specific Class
				// typeOfAnnotationValue = typeCast ? field.getType() :
				// String.class; dataToAssign =
				// AnnotationUtils.retrieveAnnotationValue(
				// typeOfAnnotationValue, annotation, "value");

				throw new RuntimeException("Not supported");
			}
		}
		assignField(field, invokeOn, dataToAssign, overrideSecurity, typeCast);
	}

	/**
	 * get a field object for a class, potentially in superclasses
	 *
	 * @param theClass
	 * @param fieldName
	 * @param callOnSupers
	 *            true if superclasses should be looked in for the field
	 * @param throwExceptionIfNotFound
	 *            will throw runtime exception if not found
	 * @return the field object or null if not found (or exception if param is
	 *         set)
	 */
	public static Field field(Class theClass, String fieldName,
			boolean callOnSupers, boolean throwExceptionIfNotFound) {
		try {
			Field field = theClass.getDeclaredField(fieldName);
			// found it
			return field;
		} catch (NoSuchFieldException e) {
			// if method not found
			// if traversing up, and not Object, and not instance method
			if (callOnSupers && !theClass.equals(Object.class)) {
				return field(theClass.getSuperclass(), fieldName, callOnSupers,
						throwExceptionIfNotFound);
			}
		}
		// maybe throw an exception
		if (throwExceptionIfNotFound) {
			throw new RuntimeException("Cant find field: " + fieldName
					+ ", in: " + theClass + ", callOnSupers: " + callOnSupers);
		}
		return null;
	}

	/**
	 * assign data to a field
	 *
	 * @param field
	 *            is the field to assign to
	 * @param invokeOn
	 *            to call on or null for static
	 * @param dataToAssign
	 *            data
	 * @param overrideSecurity
	 *            true to call on protected or private etc methods
	 * @param typeCast
	 *            true if we should typecast
	 */
	public static void assignField(Field field, Object invokeOn,
			Object dataToAssign, boolean overrideSecurity, boolean typeCast) {

		try {
			Class fieldType = field.getType();
			// typecast
			if (typeCast) {
				dataToAssign =
						typeCast(dataToAssign, fieldType,
								true, true);
			}
			if (overrideSecurity) {
				field.setAccessible(true);
			}
			field.set(invokeOn, dataToAssign);
		} catch (Exception e) {
			throw new RuntimeException("Cant assign reflection field: "
					+ (field == null ? null : field.getName()) + ", on: "
					+ className(invokeOn) + ", with args: "
					+ classNameCollection(dataToAssign), e);
		}
	}

	/**
	 * If necessary, convert an object to another type.  if type is Object.class, just return the input.
	 * Do not convert null to an empty primitive
	 * @param <T> is template type
	 * @param value
	 * @param theClass
	 * @return the object of that instance converted into something else
	 */
	public static <T> T typeCast(Object value, Class<T> theClass) {
		//default behavior is not to convert null to empty primitive
		return typeCast(value, theClass, false, false);
	}

	/**
	 * If necessary, convert an object to another type.  if type is Object.class, just return the input
	 * @param <T> is the type to return
	 * @param value
	 * @param theClass
	 * @param convertNullToDefaultPrimitive if the value is null, and theClass is primitive, should we
	 * convert the null to a primitive default value
	 * @param useNewInstanceHooks if theClass is not recognized, then honor the string "null", "newInstance",
	 * or get a constructor with one param, and call it
	 * @return the object of that instance converted into something else
	 */
	@SuppressWarnings("unchecked")
	public static <T> T typeCast(Object value, Class<T> theClass,
			boolean convertNullToDefaultPrimitive, boolean useNewInstanceHooks) {

		if (Object.class.equals(theClass)) {
			return (T)value;
		}

		if (value==null) {
			if (convertNullToDefaultPrimitive && theClass.isPrimitive()) {
				if ( theClass == boolean.class ) {
					return (T)Boolean.FALSE;
				}
				if ( theClass == char.class ) {
					return (T)(Object)0;
				}
				//convert 0 to the type
				return typeCast(0, theClass, false, false);
			}
			return null;
		}

		if (theClass.isInstance(value)) {
			return (T)value;
		}

		//if array, get the base class
		if (theClass.isArray() && theClass.getComponentType() != null) {
			theClass = (Class<T>)theClass.getComponentType();
		}
		Object resultValue = null;
		if (theClass.equals(String.class)) {
			resultValue = value == null ? null : value.toString();
		} else if (theClass.equals(value.getClass())) {
			resultValue = value;
		} else {
			throw new RuntimeException("Cannot convert from type: " + value.getClass() + " to type: " + theClass);
		}

		return (T)resultValue;
	}

	/**
	 * Construct a class
	 * @param <T> template type
	 * @param theClass
	 * @return the instance
	 */
	public static <T> T newInstance(Class<T> theClass) {
		try {
			return theClass.newInstance();
		} catch (Throwable e) {
			if (theClass != null && Modifier.isAbstract(theClass.getModifiers())) {
				throw new RuntimeException("Problem with class: " + theClass + ", maybe because it is abstract!", e);
			}
			throw new RuntimeException("Problem with class: " + theClass, e);
		}
	}

	/**
	 * close a connection null safe and dont throw exception
	 * @param connection
	 */
	public static void closeQuietly(Connection connection) {
		if (connection != null) {
			try {
				connection.close();
			} catch (Exception e) {
				//ignore
			}
		}
	}

	/**
	 * Unconditionally close an <code>InputStream</code>.
	 * Equivalent to {@link InputStream#close()}, except any exceptions will be ignored.
	 * @param input A (possibly null) InputStream
	 */
	public static void closeQuietly(InputStream input) {
		if (input == null) {
			return;
		}

		try {
			input.close();
		} catch (IOException ioe) {
		}
	}

	/**
	 * Unconditionally close an <code>OutputStream</code>.
	 * Equivalent to {@link OutputStream#close()}, except any exceptions will be ignored.
	 * @param output A (possibly null) OutputStream
	 */
	public static void closeQuietly(OutputStream output) {
		if (output == null) {
			return;
		}

		try {
			output.close();
		} catch (IOException ioe) {
		}
	}

	/**
	 * Unconditionally close an <code>Reader</code>.
	 * Equivalent to {@link Reader#close()}, except any exceptions will be ignored.
	 *
	 * @param input A (possibly null) Reader
	 */
	public static void closeQuietly(Reader input) {
		if (input == null) {
			return;
		}

		try {
			input.close();
		} catch (IOException ioe) {
		}
	}

	/**
	 * close a resultSet null safe and dont throw exception
	 * @param resultSet
	 */
	public static void closeQuietly(ResultSet resultSet) {
		if (resultSet != null) {
			try {
				resultSet.close();
			} catch (Exception e) {
				//ignore
			}
		}
	}

	/**
	 * close a statement null safe and dont throw exception
	 * @param statement
	 */
	public static void closeQuietly(Statement statement) {
		if (statement != null) {
			try {
				statement.close();
			} catch (Exception e) {
				//ignore
			}
		}
	}

	/**
	 * close a writer quietly
	 * @param writer
	 */
	public static void closeQuietly(Writer writer) {
		if (writer != null) {
			try {
				writer.close();
			} catch (IOException e) {
				//swallow, its ok
			}
		}
	}

	/**
	 * close a writer quietly
	 * @param writer
	 */
	public static void closeQuietly(XMLStreamWriter writer) {
		if (writer != null) {
			try {
				writer.close();
			} catch (XMLStreamException e) {
				//swallow, its ok
			}
		}
	}

}
