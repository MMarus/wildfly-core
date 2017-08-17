/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.domain.management.security.adduser;

import org.aesh.readline.terminal.Key;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;

/**
 * Created by Marek Marusic <mmarusic@redhat.com> on 8/9/17.
 */
public class AeshJavaConsoleTest {

    @Test
    public void testLeftArrow() throws IOException, InterruptedException {
        TestJavaConsoleThread javaConsoleThread = new TestJavaConsoleThread();
        javaConsoleThread.start();
        Thread.sleep(100);

        javaConsoleThread.write("Foo");
        javaConsoleThread.write(Key.LEFT);
        javaConsoleThread.write("F");
        javaConsoleThread.write(Key.ENTER);
        javaConsoleThread.flushWrites();

        Thread.sleep(100);
        assertEquals("FoFo", javaConsoleThread.getLine());
    }

    @Test
    public void testUpArrow() throws IOException, InterruptedException {
        TestJavaConsoleThread javaConsoleThread = new TestJavaConsoleThread();
        javaConsoleThread.start();
        Thread.sleep(100);

        javaConsoleThread.write("Foo");
        javaConsoleThread.write(Key.UP);
        javaConsoleThread.write("F");
        javaConsoleThread.write(Key.ENTER);
        javaConsoleThread.flushWrites();

        Thread.sleep(100);
        assertEquals("FooF", javaConsoleThread.getLine());
    }

    @Test
    public void testInterruptionSignal() throws IOException, InterruptedException {
        TestJavaConsoleThread javaConsoleThread = new TestJavaConsoleThread();
        javaConsoleThread.start();
        Thread.sleep(100);

        javaConsoleThread.write("Foo".getBytes());
        javaConsoleThread.write(Key.CTRL_C.getKeyValuesAsString().getBytes());
        javaConsoleThread.flushWrites();

        Thread.sleep(100);
        assertEquals(false, javaConsoleThread.isAlive());
        assertEquals(Thread.State.TERMINATED, javaConsoleThread.getState());
    }

}