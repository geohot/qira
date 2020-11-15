<?xml version="1.0" encoding="ISO-8859-15" ?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:template match="/" mode="fcode">

    <xsl:text>&#10;#&#10;# fcode rules&#10;#&#10;&#10;</xsl:text>

    <!-- Create linker targets for FCode roms -->
    <xsl:for-each select="//fcode">
     <xsl:variable name="outer-conditions">
      <xsl:text>0</xsl:text>
       <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
        <xsl:call-template name="resolve-condition">
         <xsl:with-param select="@condition" name="expression"/>
        </xsl:call-template>
       </xsl:for-each>
     </xsl:variable>

     <xsl:if test="$outer-conditions = 0">
      <xsl:if test="(ancestor-or-self::*)">

       <xsl:variable name="path">
        <xsl:for-each select="ancestor::build">
         <xsl:call-template name="get-dirname">
          <xsl:with-param select="@base" name="path"/>
         </xsl:call-template>
        </xsl:for-each>
       </xsl:variable>

       <!-- Fcode name -->
       <xsl:text>$(ODIR)/</xsl:text>
       <xsl:value-of select="@name"/>
       <xsl:text>:</xsl:text>

       <xsl:text> $(SRCDIR)/</xsl:text>
       <xsl:value-of select="$path"/>
       <xsl:value-of select="@source"/>

       <!-- FIXME this requires strict spaces in rules.xml -->
       <xsl:value-of select="document('rules.xml',.)//rule[@target='host'][@entity='fcode']"/>
       <xsl:text>&#10;</xsl:text>
      </xsl:if>
     </xsl:if>
    </xsl:for-each>

  </xsl:template>
</xsl:stylesheet>
