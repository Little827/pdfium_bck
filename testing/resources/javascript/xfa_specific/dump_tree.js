// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

function dumpTree(node, level) {
 level = level || 0;
 var indentation = " ".repeat(level);
 try {
   app.alert(indentation + "<" + node.className + ">");
   var children = node.nodes;
   for (var i = 0; i < children.length; ++i) {
     dumpTree(children.item(i), level + 1);
    }
  } catch (e) {
     app.alert(indentation + "Error: " + e);
  }
}
