
package views.html

import _root_.play.twirl.api.TwirlFeatureImports._
import _root_.play.twirl.api.TwirlHelperImports._
import _root_.play.twirl.api.Html
import _root_.play.twirl.api.JavaScript
import _root_.play.twirl.api.Txt
import _root_.play.twirl.api.Xml

object hello extends _root_.play.twirl.api.BaseScalaTemplate[play.twirl.api.HtmlFormat.Appendable,_root_.play.twirl.api.Format[play.twirl.api.HtmlFormat.Appendable]](play.twirl.api.HtmlFormat) with _root_.play.twirl.api.Template0[play.twirl.api.HtmlFormat.Appendable] {

  /**/
  def apply/*1.2*/():play.twirl.api.HtmlFormat.Appendable = {
    _display_ {
      {


Seq[Any](format.raw/*1.4*/("""
"""),_display_(/*2.2*/layouts/*2.9*/.html.default("Scalatra: a tiny, Sinatra-like web framework for Scala", "Welcome to Scalatra")/*2.103*/{_display_(Seq[Any](format.raw/*2.104*/("""
  """),format.raw/*3.3*/("""<p>Hello, Twirl!</p>
""")))}))
      }
    }
  }

  def render(): play.twirl.api.HtmlFormat.Appendable = apply()

  def f:(() => play.twirl.api.HtmlFormat.Appendable) = () => apply()

  def ref: this.type = this

}


              /*
                  -- GENERATED --
                  DATE: Wed Sep 11 10:59:57 KST 2019
                  SOURCE: /home/kevin/autoVAS/newJoern/joern/joern-server/src/main/twirl/views/hello.scala.html
                  HASH: 6a5309d0d842c7b54c83aa665c985afefdc12c70
                  MATRIX: 559->1|655->3|682->5|696->12|799->106|838->107|867->110
                  LINES: 14->1|19->1|20->2|20->2|20->2|20->2|21->3
                  -- GENERATED --
              */
          