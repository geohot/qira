<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

 <!-- 
 Stefans own xinclude implementation.
 We really don't want to bother the users with namespaces
 -->
 
 <xsl:output method="xml" indent="yes"/>
 <xsl:strip-space elements="*"/>

 <xsl:template match="node() | @*">
  <xsl:copy>
   <xsl:apply-templates select="@* | node()"/>
  </xsl:copy>
 </xsl:template>
 
 
<!-- <xsl:template match="xi:include" xmlns:xi="http://www.w3.org/2001/XInclude"> -->
 <xsl:template match="include">
  <xsl:variable name="href"><xsl:value-of select="@href"/>
  </xsl:variable>
  <xsl:for-each select="document(@href)">
   <!--
   <xsl:copy><xsl:copy-of select="@*"/>
   <xsl:attribute name="base">
     <xsl:value-of select="$href"/>
   </xsl:attribute>
   <xsl:apply-templates select="node()" />
   </xsl:copy>
   -->
   <xsl:element name="{local-name(*)}" namespace="{namespace-uri(..)}">
    <xsl:copy-of select="*/@*"/>
    <xsl:attribute name="base">
     <xsl:value-of select="$href"/>
    </xsl:attribute>
    <xsl:for-each select="*">
     <xsl:apply-templates/>
    </xsl:for-each>
   </xsl:element>
  </xsl:for-each>
 </xsl:template>
 
</xsl:stylesheet>
