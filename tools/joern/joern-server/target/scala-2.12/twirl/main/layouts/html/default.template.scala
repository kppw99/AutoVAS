
package layouts.html

import _root_.play.twirl.api.TwirlFeatureImports._
import _root_.play.twirl.api.TwirlHelperImports._
import _root_.play.twirl.api.Html
import _root_.play.twirl.api.JavaScript
import _root_.play.twirl.api.Txt
import _root_.play.twirl.api.Xml

object default extends _root_.play.twirl.api.BaseScalaTemplate[play.twirl.api.HtmlFormat.Appendable,_root_.play.twirl.api.Format[play.twirl.api.HtmlFormat.Appendable]](play.twirl.api.HtmlFormat) with _root_.play.twirl.api.Template3[String,String,Html,play.twirl.api.HtmlFormat.Appendable] {

  /**/
  def apply/*1.2*/(title: String, headline: String)(body: Html):play.twirl.api.HtmlFormat.Appendable = {
    _display_ {
      {


Seq[Any](format.raw/*1.47*/("""
"""),format.raw/*2.1*/("""<html>
  <head>
    <title>"""),_display_(/*4.13*/title),format.raw/*4.18*/("""</title>
  </head>
  <body>
    <h1>"""),_display_(/*7.10*/headline),format.raw/*7.18*/("""</h1>
    """),_display_(/*8.6*/body),format.raw/*8.10*/("""
  """),format.raw/*9.3*/("""</body>
</html>"""))
      }
    }
  }

  def render(title:String,headline:String,body:Html): play.twirl.api.HtmlFormat.Appendable = apply(title,headline)(body)

  def f:((String,String) => (Html) => play.twirl.api.HtmlFormat.Appendable) = (title,headline) => (body) => apply(title,headline)(body)

  def ref: this.type = this

}


              /*
                  -- GENERATED --
                  DATE: Wed Sep 11 10:59:57 KST 2019
                  SOURCE: /home/kevin/autoVAS/newJoern/joern/joern-server/src/main/twirl/layouts/default.scala.html
                  HASH: ab59b4dddbafceb665de3cb0f7ce9f2c8dc5df51
                  MATRIX: 582->1|722->46|749->47|803->75|828->80|891->117|919->125|955->136|979->140|1008->143
                  LINES: 14->1|19->1|20->2|22->4|22->4|25->7|25->7|26->8|26->8|27->9
                  -- GENERATED --
              */
          