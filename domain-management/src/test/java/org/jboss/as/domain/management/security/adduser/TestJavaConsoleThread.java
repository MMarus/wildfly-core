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

import org.aesh.readline.tty.terminal.TerminalConnection;
import org.aesh.readline.terminal.Key;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.Charset;

/**
 * Created by Marek Marusic <mmarusic@redhat.com> on 8/14/17.
 */
public class TestJavaConsoleThread extends Thread {
    private PipedOutputStream pipedOutputStream;
    private PipedInputStream pipedInputStream;
    private ByteArrayOutputStream out;
    private String line;

    public TestJavaConsoleThread() {
        try {
            pipedOutputStream = new PipedOutputStream();
            pipedInputStream = new PipedInputStream(pipedOutputStream);
            out = new ByteArrayOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getLine() {
        return line;
    }

    public void flushWrites() {
        try {
            pipedOutputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void write(String data) {
        write(data.getBytes());
    }

    public void write(byte[] data) {
        try {
            pipedOutputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void write(Key key) {
        write(key.getKeyValuesAsString().getBytes());
    }

    public void run() {
        System.out.println("Running " + "Thread");
        // Create JavaConsole with custom input, output streams for testing
        JavaConsole javaConsole = new JavaConsole() {
            @Override
            protected void createTerminalConnection(ReadLineHandler readLineHandler) throws IOException {
                TerminalConnection conn = new TerminalConnection(Charset.defaultCharset(), pipedInputStream, out,
                        readLineHandler);
            }
        };

        line = javaConsole.readLine("[Prompt:]");
    }
}
