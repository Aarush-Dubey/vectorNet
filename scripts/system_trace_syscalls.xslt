<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text" encoding="UTF-8"/>
  <xsl:param name="mode" select="'rx'"/>
  <xsl:key name="by-id" match="*[@id]" use="@id"/>

  <xsl:template name="resolved-value">
    <xsl:param name="node"/>
    <xsl:choose>
      <xsl:when test="$node/@ref">
        <xsl:value-of select="key('by-id', $node/@ref)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$node"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="/">
    <xsl:text>start_ns,syscall,duration_ns,return_value&#10;</xsl:text>
    <xsl:for-each select="//row">
      <xsl:variable name="call">
        <xsl:choose>
          <xsl:when test="syscall/@fmt">
            <xsl:value-of select="syscall/@fmt"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="key('by-id', syscall/@ref)/@fmt"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:if test="($mode = 'rx' and ($call = 'read' or $call = 'kevent')) or
                    ($mode = 'tx' and $call = 'write')">
        <xsl:call-template name="resolved-value">
          <xsl:with-param name="node" select="start-time"/>
        </xsl:call-template>
        <xsl:text>,</xsl:text>
        <xsl:value-of select="$call"/>
        <xsl:text>,</xsl:text>
        <xsl:call-template name="resolved-value">
          <xsl:with-param name="node" select="duration"/>
        </xsl:call-template>
        <xsl:text>,</xsl:text>
        <xsl:call-template name="resolved-value">
          <xsl:with-param name="node" select="syscall-return[1]"/>
        </xsl:call-template>
        <xsl:text>&#10;</xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
