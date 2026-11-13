# syntax=docker/dockerfile:1

# ---- build -------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src

COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/FieldCrypto/FieldCrypto.csproj src/FieldCrypto/
COPY src/FieldCrypto.Oci/FieldCrypto.Oci.csproj src/FieldCrypto.Oci/
COPY src/FieldCrypto.EntityFrameworkCore/FieldCrypto.EntityFrameworkCore.csproj src/FieldCrypto.EntityFrameworkCore/
COPY src/FieldCrypto.Dapper/FieldCrypto.Dapper.csproj src/FieldCrypto.Dapper/
COPY samples/FieldCrypto.Demo/FieldCrypto.Demo.csproj samples/FieldCrypto.Demo/
RUN --mount=type=cache,id=fieldcrypto-nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet restore samples/FieldCrypto.Demo/FieldCrypto.Demo.csproj

COPY .editorconfig ./
COPY src/ src/
COPY samples/FieldCrypto.Demo/ samples/FieldCrypto.Demo/
RUN --mount=type=cache,id=fieldcrypto-nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet publish samples/FieldCrypto.Demo/FieldCrypto.Demo.csproj \
        --configuration Release --output /app/publish -p:UseAppHost=false

# ---- runtime -----------------------------------------------------------------------------------------
# The ASP.NET chiseled image also runs console apps; it is the runtime base the KMS image already uses.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime
LABEL org.opencontainers.image.title="fieldcrypto-demo" \
      org.opencontainers.image.source="https://github.com/hekimcan206/field-crypto" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build --link /app/publish .
USER $APP_UID
ENTRYPOINT ["dotnet", "FieldCrypto.Demo.dll"]
